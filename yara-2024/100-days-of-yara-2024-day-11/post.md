# 100 Days of Yara in 2024: Day 11
We have some more load commands to parse! This time around, we're going to be parsing the `LC_SOURCE_VERSION` load command. It allows us to garner more data about the development environment of the binary, if it is included. It could also be used to narrow or tune what you're looking for. 


## The Data Layout
Again, we are going to use our trusty [`loader.h`](https://opensource.apple.com/source/xnu/xnu-4570.1.46/EXTERNAL_HEADERS/mach-o/loader.h.auto.html) file for Mach-O binaries. It indentifies the structure for the load command as such:

```c
/*
 * The source_version_command is an optional load command containing
 * the version of the sources used to build the binary.
 */
struct source_version_command {
    uint32_t  cmd;	/* LC_SOURCE_VERSION */
    uint32_t  cmdsize;	/* 16 */
    uint64_t  version;	/* A.B.C.D.E packed as a24.b10.c10.d10.e10 */
};
```

I mapped the source version data out into the following structure in Rust:

```rust
/// `SourceVersionCommand`: Represents a source version load command
/// in the Mach-O file.
/// Fields: cmd, cmdsize, version
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct SourceVersionCommand {
    cmd: u32,
    cmdsize: u32,
    version: u64,
}
```

## Parsing the Data
This one is pretty straight forward to parse out, the command identifier is a uint32, the size is a uint32, and the version is a uint64. The only part that requires some effort is parsing the version from the bitfield into the appropriate format.

The format is defined as so in the file:
```
uint64_t  version;	/* A.B.C.D.E packed as a24.b10.c10.d10.e10 */
```

I wrote a handy helper function to convert the bitfield into the format:
```rust
/// Convert a decimal number representation to a source version string representation in a Mach-O.
/// The decimal number is expected to be in the format
/// `A.B.C.D.E packed as a24.b10.c10.d10.e10`.
///
/// # Arguments
///
/// * `decimal_number`: The decimal number to convert.
///
/// # Returns
///
/// A string representation of the version number.
fn convert_to_source_version_string(decimal_number: u64) -> String {
    let mask = 0x3f;
    let a = decimal_number >> 40;
    let b = (decimal_number >> 30) & mask;
    let c = (decimal_number >> 20) & mask;
    let d = (decimal_number >> 10) & mask;
    let e = decimal_number & mask;
    format!("{}.{}.{}.{}.{}", a, b, c, d, e)
}
```


### Handling Function
The handling function involves some error checking, invoking the parsing function, and setting the relevant details in the protobuf representation.
```rust
fn handle_source_version_command(
    command_data: &[u8],
    size: usize,
    macho_file: &mut File,
) -> Result<(), MachoError> {
    if size < std::mem::size_of::<SourceVersionCommand>() {
        return Err(MachoError::FileSectionTooSmall(
            "SourceVersion".to_string(),
        ));
    }

    let (_, mut sv) = parse_source_version_command(command_data)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;

    if should_swap_bytes(
        macho_file
            .magic
            .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
    ) {
        swap_source_version_command(&mut sv);
    };

    macho_file.source_version =
        Some(convert_to_source_version_string(sv.version));

    Ok(())
}
```

### Parsing Function
The parsing function will be called by the handling function above. We have a single parsing function defined:

```rust
/// Parse a Mach-O SourceVersionCommand, transforming raw bytes into a
/// structured format.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw SourceVersionCommand data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining unparsed input and the parsed
/// SourceVersionCommand structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_source_version_command(
    input: &[u8],
) -> IResult<&[u8], SourceVersionCommand> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;
    let (input, version) = le_u64(input)?;
    Ok((input, SourceVersionCommand { cmd, cmdsize, version }))
}
```

## End Result
Our test binaries include some binaries that have the source version field present, albeit the value is 0.0.0.0.0, but that is ok, we can still test with it. Running the tests brings about the following results:
```
[...]

    dynamic_linker: "/usr/lib/dyld"
    entry_point: 3808
    stack_size: 0
    source_version: "0.0.0.0.0"

[...]
```

## Finished Work

I added to the PR to YARA-X here: [#67](https://github.com/VirusTotal/yara-x/pull/67) :)