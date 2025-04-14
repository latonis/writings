# 100 Days of Yara in 2024: Day 30
In [Day 28](https://jacoblatonis.me/posts/100-days-of-yara-2024-day-28), I went over the parsing structure change for YARA-X's Mach-O module. In [Day 29](https://jacoblatonis.me/posts/100-days-of-yara-2024-day-29), I went over reworking my current PR for parsing code signature data. Now, we're going to rework the entitlements parsing as well!

## Original Way
When parsing the entitlements data from Mach-o binaries, I had written it for the old way. Let's take a look at what that looks like in Rust:

```rust
/// `CSBlob`: Represents a CSBlob structure in the Mach-O file.
/// Fields: magic, length
#[derive(Debug, Default, Clone, Copy)]
struct CSBlob {
    magic: u32,
    length: u32,
}

/// `CSBlobIndex`: Represents a BlobIndex structure in the Mach-O file.
/// Fields: blobtype, offset, blob
#[derive(Debug, Default, Clone, Copy)]
struct CSBlobIndex {
    _blobtype: u32,
    offset: u32,
    blob: CSBlob,
}

/// `CSSuperBlob`: Represents a CSSuperBlob structure in the Mach-O file.
/// Fields: magic, length, count, index
#[derive(Debug, Default, Clone)]
struct CSSuperBlob {
    _magic: u32,
    _length: u32,
    count: u32,
    index: Vec<CSBlobIndex>,
}

/// Parse the embedded-signature CSBlob structure for code signature data for a Mach-O.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw code signature blob.
///
/// # Returns
///
/// A `nom` IResult containing the remaining input and the parsed
/// CSBlob structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_cs_blob(input: &[u8]) -> IResult<&[u8], CSBlob> {
    let (input, magic) = be_u32(input)?;
    let (input, length) = be_u32(input)?;

    Ok((input, CSBlob { magic, length }))
}

/// Parse the embedded-signature CSBlobIndex structure for code signature data for a Mach-O.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw code signature blob index.
///
/// # Returns
///
/// A `nom` IResult containing the remaining input and the parsed
/// CSBlobIndex structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_cs_index(input: &[u8]) -> IResult<&[u8], CSBlobIndex> {
    let (input, blobtype) = be_u32(input)?;
    let (input, offset) = be_u32(input)?;

    Ok((
        input,
        CSBlobIndex { _blobtype: blobtype, offset, ..Default::default() },
    ))
}

/// Parse the embedded-signature SuperBlob for code signature data for a Mach-O.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw code signature superblob data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining input and the parsed
/// CSSuperBlob structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_cs_superblob(data: &[u8]) -> IResult<&[u8], CSSuperBlob> {
    // CSSuperBlobs are already network byte order, which is BE
    let (input, magic) = be_u32(data)?;
    let (input, length) = be_u32(input)?;
    let (input, count) = be_u32(input)?;

    let mut super_blob = CSSuperBlob {
        _magic: magic,
        _length: length,
        count,
        ..Default::default()
    };

    let mut input: &[u8] = input;
    let mut cs_index: CSBlobIndex;

    for _ in 0..super_blob.count {
        (input, cs_index) = parse_cs_index(input)?;

        let offset = cs_index.offset as usize;

        let (_, blob) = parse_cs_blob(&data[offset..])?;

        cs_index.blob = blob;
        super_blob.index.push(cs_index);
    }

    Ok((input, super_blob))
}

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
                        [...]
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

You can see above, we have a parsing function, a handling function, and then more parsing functions for each code signature blob and structure type. It's a fair amount of code.

## New Way
The new way is a little simpler to look at in my opinion.

```rust
        if let Some(ref code_signature_data) = macho.code_signature_data {
            let offset = code_signature_data.dataoff as usize;
            let size = code_signature_data.datasize as usize;
            let super_data = &data[offset..offset + size];
            if let Err(_err) = macho.cs_superblob()(super_data) {
                #[cfg(feature = "logging")]
                error!("Error parsing Mach-O file: {:?}", _err);
                // fail silently if it fails, data was not formatted
                // correctly but parsing should still proceed for
                // everything else
            };
        }

        fn cs_blob(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], CSBlob> + '_ {
        move |input: &'a [u8]| {
            let (_, (magic, length)) = tuple((
                u32(Endianness::Big), // magic
                u32(Endianness::Big), // length,
            ))(input)?;

            Ok((&[], CSBlob { magic, length }))
        }
    }

    fn cs_index(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], CSBlobIndex> + '_ {
        move |input: &'a [u8]| {
            let (input, (blobtype, offset)) = tuple((
                u32(Endianness::Big), // blobtype
                u32(Endianness::Big), // offset,
            ))(input)?;

            Ok((input, CSBlobIndex { blobtype, offset, blob: None }))
        }
    }

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
                            let xml_data = &super_data
                                [offset + size_of_blob..offset + length];
                            let xml_string = std::str::from_utf8(xml_data)
                                .unwrap_or_default();

                            let opt = roxmltree::ParsingOptions {
                                allow_dtd: true,
                                ..roxmltree::ParsingOptions::default()
                            };

                            if let Ok(parsed_xml) =
                                roxmltree::Document::parse_with_options(
                                    xml_string, opt,
                                )
                            {
                                for node in parsed_xml
                                    .descendants()
                                    .filter(|n| n.has_tag_name("key"))
                                {
                                    if let Some(entitlement) = node.text() {
                                        self.entitlements
                                            .push(entitlement.to_string());
                                    }
                                }
                            }
                        }
                        CS_MAGIC_BLOBWRAPPER => {
                            // TODO: Parse certificates
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