# 100 Days of Yara in 2024: Day 31
Following the theme of the last few days of my [#100DaysofYARA](https://twitter.com/hashtag/100DaysofYARA?src=hashtag_click) posts, I am once again refactoring a portion of a PR to follow the new parsing format and methodology for the Mach-O module and YARA-X.

## Original Way
When parsing the code signature data from Mach-o binaries, I had written it for the old way. Let's take a look at what that looks like in Rust:

```rust
/// Processes the code signature data based on the values calculated
/// from the LC_CODE_SIGNATURE load command.
///
/// # Arguments
///
/// * `data`: The raw byte data of the Mach-O file.
/// * `macho_file`: The protobuf representation of the Mach-O file to be populated.
///
/// # Returns
///
/// Returns a `Result<(), MachoError>` indicating the success or failure of the
/// parsing operation.
fn parse_macho_code_signature(
    data: &[u8],
    macho_file: &mut File,
) -> Result<(), MachoError> {
    if macho_file.code_signature_data.is_some() {
        let code_signature_data =
            macho_file.code_signature_data.as_mut().unwrap();
        let data_offset = code_signature_data.dataoff() as usize;
        let data_size = code_signature_data.datasize() as usize;

        if data_offset < data.len() {
            let super_data = &data[data_offset..data_offset + data_size];
            let (_, super_blob) = parse_cs_superblob(super_data)
                .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;

            for blob_index in super_blob.index {
                let offset = blob_index.offset as usize;
                let length = blob_index.blob.length as usize;
                let size_of_blob = std::mem::size_of::<CSBlob>();

                match blob_index.blob.magic {
                    CS_MAGIC_BLOBWRAPPER => {
                        let certificates =
                            macho_file.certificates.mut_or_insert_default();

                        let signage = SignedData::parse_ber(
                            &super_data
                                [offset + size_of_blob..offset + length],
                        )
                        .map_err(|e| {
                            MachoError::ParsingError(format!("{:?}", e))
                        })?;

                        let signers = signage.signers();
                        let certs = signage.certificates();

                        certs.for_each(|cert| {
                            let name = cert.subject_common_name().unwrap();
                            certificates.common_names.push(name);
                        });

                        signers.for_each(|signer| {
                            let (name, _) = signer
                                .certificate_issuer_and_serial()
                                .unwrap();
                            certificates.signer_names.push(
                                name.user_friendly_str().unwrap().to_string(),
                            );
                        });
                    }
                    CS_MAGIC_EMBEDDED_ENTITLEMENTS => {
                        let xml_data = &super_data
                            [offset + size_of_blob..offset + length];
                        let xml_string =
                            std::str::from_utf8(xml_data).unwrap_or_default();

                        let opt = roxmltree::ParsingOptions {
                            allow_dtd: true,
                            ..roxmltree::ParsingOptions::default()
                        };

                        let parsed_xml =
                            roxmltree::Document::parse_with_options(
                                xml_string, opt,
                            )
                            .map_err(|e| {
                                MachoError::ParsingError(format!("{:?}", e))
                            })?;

                        for node in parsed_xml
                            .descendants()
                            .filter(|n| n.has_tag_name("key"))
                        {
                            if let Some(entitlement) = node.text() {
                                macho_file
                                    .entitlements
                                    .push(entitlement.to_string());
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}
```

Admittedly, this one didn't change all that much. Instead of having a separate parsing function for the SuperBlob and the code signature data after, I decided to parse the different blobs while parsing the SuperBlob instead of after the fact in the new way. You can find that below

## New Way
The new way is a little simpler and easier to follow in my opinion. When encountering the magic bytes of `CS_MAGIC_BLOBWRAPPER` (0xfade0b01), we know it is time to parse the code signing certificates, which are in BER format. I use the [`cryptographic_message_syntax`](https://docs.rs/cryptographic-message-syntax/latest/cryptographic_message_syntax/) crate, which supports parsing DER and BER formatted certificates defined in the cryptographic message syntax (CMS) standard ([RFC 5652](https://www.rfc-editor.org/rfc/rfc5652.txt)). From there, I can then iterate over the certificates and grab the names of the signers as well as the subject common name of each of the certificates.

```rust

    fn cs_superblob(
        &mut self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], CSSuperBlob> + '_ {
        move |data: &'a [u8]| {
            let (remainder, (_magic, _length, count)) = tuple((
                u32(Endianness::Big), // magic
                u32(Endianness::Big), // offset,
                u32(Endianness::Big), // count,
            ))(data)?;

            let mut super_blob =
                CSSuperBlob { _magic, _length, count, index: Vec::new() };

            let mut input: &[u8] = remainder;
            let mut cs_index: CSBlobIndex;

            for _ in 0..super_blob.count {
                (input, cs_index) = self.cs_index()(input)?;
                let offset: usize = cs_index.offset as usize;
                let (_, blob) = self.cs_blob()(&data[offset..])?;

                cs_index.blob = Some(blob);
                super_blob.index.push(cs_index);
            }

            let super_data = data;

            for blob_index in &super_blob.index {
                let _blob_type = blob_index.blobtype as usize;
                if let Some(blob) = &blob_index.blob {
                    let offset = blob_index.offset as usize;
                    let length = blob.length as usize;
                    let size_of_blob = std::mem::size_of::<CSBlob>();
                    match blob.magic {
                        CS_MAGIC_EMBEDDED_ENTITLEMENTS => {
                           [...]
                        }
                        CS_MAGIC_BLOBWRAPPER => {
                            if let Ok(signage) = SignedData::parse_ber(
                                &super_data
                                    [offset + size_of_blob..offset + length],
                            ) {
                                let signers = signage.signers();
                                let certs = signage.certificates();
                                let mut cert_info = Certificates {
                                    common_names: Vec::new(),
                                    signer_names: Vec::new(),
                                };

                                certs.for_each(|cert| {
                                    let name =
                                        cert.subject_common_name().unwrap();
                                    cert_info.common_names.push(name);
                                });

                                signers.for_each(|signer| {
                                    let (name, _) = signer
                                        .certificate_issuer_and_serial()
                                        .unwrap();
                                    cert_info.signer_names.push(
                                        name.user_friendly_str()
                                            .unwrap()
                                            .to_string(),
                                    );
                                });

                                self.certificates = Some(cert_info);
                            }
                        }
                        _ => {}
                    }
                }
            }

            Ok((&[], super_blob))
        }
    }
```

## Finished Work
This is just part of the work from [#73](https://github.com/VirusTotal/yara-x/pull/73) that I am cleaning up after the refactor. There will be more posts like this :').

This specific work implemented today can be seen in [#78](https://github.com/VirusTotal/yara-x/pull/78) on YARA-X.