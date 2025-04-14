# 100 Days of Yara in 2024: Day 22
In [Day 20](https://jacoblatonis.me/posts/100-days-of-yara-2024-day-20) we talked about planning ahead, in [Day 21](https://jacoblatonis.me/posts/100-days-of-yara-2024-day-21) I talked about progress for parsing entitlements, and I'm happy to say we're now parsing entitlements for Mach-O binaries!!

## The Identifier
The identifier we need to focus on for parsing our entitlements today is the magic bytes identifier for the Blob Wrapper structures that contain our certificates we want to read for the binary.

```rust
const CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171,	/* embedded entitlements */
```

## The Data Layout
The entitlements blob is raw XML embedded in the binary. As such, I didn't define any custom data structures for this data. Instead, I used the [`roxmltree`](https://docs.rs/roxmltree/latest/roxmltree/) crate to parse the XML into a tree and then search for the nodes that had the name of `key`, as the plist format does for entitlements.

The `roxmltree` relies heavily on iterators in rust, which is great for us.

## Parsing the Data
To parse the data, we need to use the offsets from the parsed superblob, blob index, and data blobs. We then locate the correct bob via the magic bytes and then parse the XML/plist.

### Handling Function
My main parsing/handling function does collection of the structures, offset calculations, some error handling, and populating the protobuf representation with the needed data. We have improved on the `parse_macho_code_signature()` function implemented in [Day 19](https://jacoblatonis.me/posts/100-days-of-yara-2024-day-19).

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

## End Result
The chess binary from Day 19 also has entitlements, so I used those to test and update the Goldenfiles.

```
entitlements:
  - "com.apple.developer.game-center"
  - "com.apple.private.tcc.allow"
  - "com.apple.security.app-sandbox"
  - "com.apple.security.device.microphone"
  - "com.apple.security.files.user-selected.read-write"
  - "com.apple.security.network.client"
```

## Finished Work

I submitted a PR to YARA-X  here: [#73](https://github.com/VirusTotal/yara-x/pull/73) :)