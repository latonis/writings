# 100 Days of Yara in 2024: Day 19
In Day 18, I showed I was making progress on parsing code certificates. I am glad to say I've parsed them successfully and have made substantial progress on quite a few parts of Mach-O binaries and how the certificate and signing system works.

## The Identifier
The identifier we need to focus on for parsing our code signature data today is the magic bytes identifier for the Blob Wrapper structures that contain our certificates we want to read for the binary.

```rust
const CS_MAGIC_BLOBWRAPPER: u32 = 0xfade0b01;
```

## The Data Layout
There's a few different source files were interested in today: `cscdefs.h`, `codesign.h`, and our trusty `loader.h`. The structures we plan on parsing are as follows:
```c
typedef struct __BlobIndex {
	uint32_t type;					/* type of entry */
	uint32_t offset;				/* offset of entry */
} CS_BlobIndex;

typedef struct __SuperBlob {
	uint32_t magic;					/* magic number */
	uint32_t length;				/* total length of SuperBlob */
	uint32_t count;					/* number of index entries following */
	CS_BlobIndex index[];			/* (count) entries */
	/* followed by Blobs in no particular order as indicated by offsets in index */
} CS_SuperBlob;

typedef struct __SC_GenericBlob {
	uint32_t magic;				/* magic number */
	uint32_t length;			/* total length of blob */
	char data[];
} CS_GenericBlob;
```

I mapped this data out into the following structures in Rust. You can see that I've taken small liberties with naming and storage, as it makes it easier to use the data we've parsed out.
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
```
## Parsing the Data
There's more than a few functions for parsing the data. I'll break down the main parsing/handling function as well as each individual parsing function for each struct. The one interesting thing for all of this is that the data is always big-endian, we don't need to worry about swapping like we did for every prior parsing function.

### Handling Function
My main parsing/handling function does collection of the structures, offset calculations, some error handling, and populating the protobuf representation with the needed data.

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
        let certificates = macho_file.certificates.mut_or_insert_default();
        let code_signature_data =
            macho_file.code_signature_data.as_mut().unwrap();
        let data_offset = code_signature_data.dataoff() as usize;
        let data_size = code_signature_data.datasize() as usize;

        if data_offset < data.len() {
            let super_data = &data[data_offset..data_offset + data_size];
            let (_, super_blob) = parse_cs_superblob(super_data)
                .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;

            for blob_index in super_blob.index {
                if blob_index.blob.magic == CS_MAGIC_BLOBWRAPPER {
                    let offset = blob_index.offset as usize;
                    let length = blob_index.blob.length as usize;
                    let size_of_blob = std::mem::size_of::<CSBlob>();

                    let signage = SignedData::parse_ber(
                        &super_data[offset + size_of_blob
                            ..offset + size_of_blob + length],
                    )
                    .map_err(|e| {
                        MachoError::ParsingError(format!("{:?}", e))
                    })?;
                    // .unwrap();

                    let signers = signage.signers();
                    let certs = signage.certificates();

                    certs.for_each(|cert| {
                        let name = cert.subject_common_name().unwrap();
                        certificates.common_names.push(name);
                    });

                    signers.for_each(|signer| {
                        let (name, _) =
                            signer.certificate_issuer_and_serial().unwrap();
                        certificates.signer_names.push(
                            name.user_friendly_str().unwrap().to_string(),
                        );
                    });
                }
            }
        }
    }
    Ok(())
}
```

### Parsing Function
The parsing functions will be called by the handling function above. We have three parsing functions for the three structs defined above:

```rust
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
```

## End Result
I dug out the chess binary from MacOS to test on as well as the one binary in YARA-X test data that already had a certificate. We can see the certificates being parsed below into the Goldenfile.

```
[...]

certificates:
    common_names:
      - "Apple Code Signing Certification Authority"
      - "Apple Root CA"
      - "Software Signing"
    signer_names:
      - "CN=Apple Code Signing Certification Authority, OU=Apple Certification Authority, O=Apple Inc., C=US"

[...]
```

```
certificates:
    common_names:
      - "Developer ID Certification Authority"
      - "Apple Root CA"
      - "Developer ID Application: EFI Inc (82PCFB3NFC)"
    signer_names:
      - "CN=Developer ID Certification Authority, OU=Apple Certification Authority, O=Apple Inc., C=US"
```

## Finished Work

I submitted a PR to YARA-X  here: [#73](https://github.com/VirusTotal/yara-x/pull/73) :)