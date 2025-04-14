# 100 Days of Yara in 2024: Day 17
We've parsed a lot of metadata so far! There have been quite a few load commands parsed, but we still have more in the pipeline! The symbol table qas quite interesting, and I wanted to parse some more fun data structures, this time maybe looking into the signature data of the code!

## The Identifier
The identifier for our particular load command is as follows:

```c
#define LC_CODE_SIGNATURE 0x1d	/* local of code signature */
```

## The Data Layout
Again, we are going to use our trusty [`loader.h`](https://opensource.apple.com/source/xnu/xnu-4570.1.46/EXTERNAL_HEADERS/mach-o/loader.h.auto.html) file for Mach-O binaries. This particular load command uses the `linkedit_data_command`, which has data offsets into the file and data sizes. Multiple load commands use this, and we will likely parse it again later for a different load command.
```c
/*
 * The linkedit_data_command contains the offsets and sizes of a blob
 * of data in the __LINKEDIT segment.  
 */
struct linkedit_data_command {
    uint32_t	cmd;		/* LC_CODE_SIGNATURE, LC_SEGMENT_SPLIT_INFO,
                                   LC_FUNCTION_STARTS, LC_DATA_IN_CODE,
				   LC_DYLIB_CODE_SIGN_DRS or
				   LC_LINKER_OPTIMIZATION_HINT. */
    uint32_t	cmdsize;	/* sizeof(struct linkedit_data_command) */
    uint32_t	dataoff;	/* file offset of data in __LINKEDIT segment */
    uint32_t	datasize;	/* file size of data in __LINKEDIT segment  */
};
```

I mapped this data out into the following structures in Rust, notice I kept the naming generic, as we will likely reuse this data structure:
```rust
/// `LinkedItDataCommand`: Represents a LinkedIt Data load command in the Mach-O file.
/// Fields: cmd, cmdsize, dataoff, datasize
struct LinkedItDataCommand {
    cmd: u32,
    cmdsize: u32,
    dataoff: u32,
    datasize: u32,
}
```
## Parsing the Data
The data here is easy to parse in the begininning, it'll get more complicated later when we have structs that are not just 32-bit unsigned integers.

Looking at you `__SC_SuperBlob`!!

### Handling Function
The handling function involves some error checking, invoking the parsing function, and setting the relevant details in the protobuf representation. Right now, our match statement only has one LC to match on, but we will have all of the ones mentioned in the documentation eventually.

```rust
/// Handles the LC_CODE_SIGNATURE, LC_SEGMENT_SPLIT_INFO, LC_FUNCTION_STARTS,
/// LC_DATA_IN_CODE, LC_DYLIB_CODE_SIGN_DRS commands for Mach-O files, parsing the data
/// and populating a protobuf representation of the symtab command.
///
/// # Arguments
///
/// * `command_data`: The raw byte data of the LinkedItDataCommand.
/// * `size`: The size of the LinkedItDataCommand command data.
/// * `macho_file`: Mutable reference to the protobuf representation of the
///   Mach-O file.
///
/// # Returns
///
/// Returns a `Result<(), MachoError>` indicating the success or failure of the
/// operation.
///
/// # Errors
///
/// * `MachoError::FileSectionTooSmall`: Returned when the segment size is
///   smaller than the expected LinkedItDataCommand struct size.
/// * `MachoError::ParsingError`: Returned when there is an error parsing the
///   LinkedItDataCommand data.
/// * `MachoError::MissingHeaderValue`: Returned when the "magic" header value
///   is missing, needed for determining if bytes should be swapped.
fn handle_linkedit_data_command(
    command_data: &[u8],
    size: usize,
    macho_file: &mut File,
) -> Result<(), MachoError> {
    if size < std::mem::size_of::<LinkedItDataCommand>() {
        return Err(MachoError::FileSectionTooSmall(
            "LinkedItDataCommand".to_string(),
        ));
    }

    let (_, mut lid) = parse_linkedit_data_command(command_data)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;

    if should_swap_bytes(
        macho_file
            .magic
            .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
    ) {
        swap_linkedit_data_command(&mut lid);
    };

    // TODO: handle the other ones mentioned in the header
    match lid.cmd {
        LC_CODE_SIGNATURE => {
            macho_file.code_signature_data =
                MessageField::some(LinkedItData {
                    cmd: Some(lid.cmd),
                    cmdsize: Some(lid.cmdsize),
                    dataoff: Some(lid.dataoff),
                    datasize: Some(lid.datasize),
                    ..Default::default()
                });
        }
        _ => {}
    }

    Ok(())
}
```

### Parsing Function
The parsing function will be called by the handling function above. We have two parsing functions for a struct:

```rust
/// Parse a Mach-O LinkedItDataCommand, transforming raw bytes into a structured
/// format.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw LinkedItDataCommand data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining unparsed input and the parsed
/// LinkedItDataCommand structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_linkedit_data_command(
    input: &[u8],
) -> IResult<&[u8], LinkedItDataCommand> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;
    let (input, dataoff) = le_u32(input)?;
    let (input, datasize) = le_u32(input)?;

    Ok((input, LinkedItDataCommand { cmd, cmdsize, dataoff, datasize }))
}
```

## End Result
Thankfully, one of the binaries in the YARA-X testing data has a signature and the appropriate load command to test on!

```
[...]

code_signature_data:
    cmd: 29
    cmdsize: 16
    dataoff: 43472
    datasize: 18800

[...]
```

## Finished Work

I submitted a PR to YARA-X  here: [#73](https://github.com/VirusTotal/yara-x/pull/73) :)