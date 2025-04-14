# 100 Days of Yara in 2024: Day 37
Following the theme of the last few days of my [#100DaysofYARA](https://twitter.com/hashtag/100DaysofYARA?src=hashtag_click) posts, I am once again refactoring a portion of a PR to follow the new parsing format and methodology for the Mach-O module and YARA-X. If you remember way back in [Day 01](https://jacoblatonis.me/posts/100-days-of-yara-2024-day-01), I parsed out the `LC_UUID` load commands. Unfortunately, it now needs to be refactored as the PR ([#65](https://github.com/VirusTotal/yara-x/pull/65/files)) wasn't merged in before the refactor. As such, we have some work to do!

## Original Way
The old way involves the endianness swapping, a handler function, and a parsing function.

```rust
const LC_UUID: u32 = 0x00000001b;

/// `UUIDCommand`: Represents a uuid command in the Mach-O file.
/// Fields: cmd, cmdsize, uuid
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct UUIDCommand {
    cmd: u32,
    cmdsize: u32,
    uuid: [u8; 16],
}

/// Swaps the endianness of fields within a Mach-O UUID load command from
/// BigEndian to LittleEndian in-place.
///
/// # Arguments
///
/// * `command`: A mutable reference to the Mach-O uuid load command.
fn swap_uuid_command(command: &mut UUIDCommand) {
    command.cmd = BigEndian::read_u32(&command.cmd.to_le_bytes());
    command.cmdsize = BigEndian::read_u32(&command.cmdsize.to_le_bytes());
}

/// Parse a Mach-O UUID load command, transforming raw bytes into a structured
/// format.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw UUIDCommand data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining unparsed input and the parsed
/// UUIDCommand structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_uuid_command(input: &[u8]) -> IResult<&[u8], UUIDCommand> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;
    let (input, uuid) = take(16usize)(input)?;

    Ok((input, UUIDCommand { cmd, cmdsize, uuid: *array_ref![uuid, 0, 16] }))
}

/// Handles the LC_UUID commands for Mach-O files, parsing the data
/// and populating a protobuf representation of the UUID load command.
///
/// # Arguments
///
/// * `command_data`: The raw byte data of the rpath command.
/// * `size`: The size of the UUID load command data.
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
///   smaller than the expected UUIDCommand struct size.
/// * `MachoError::ParsingError`: Returned when there is an error parsing the
///   UUID load command data.
/// * `MachoError::MissingHeaderValue`: Returned when the "magic" header value
///   is missing, needed for determining if bytes should be swapped.
fn handle_uuid_command(
    command_data: &[u8],
    size: usize,
    macho_file: &mut File,
) -> Result<(), MachoError> {
    if size < std::mem::size_of::<UUIDCommand>() {
        return Err(MachoError::FileSectionTooSmall(
            "UUIDCommand".to_string(),
        ));
    }

    let (_, mut uc) = parse_uuid_command(command_data)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;
    if should_swap_bytes(
        macho_file
            .magic
            .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
    ) {
        swap_uuid_command(&mut uc);
    }

    let mut uuid_str = String::new();

    for (idx, c) in uc.uuid.iter().enumerate() {
        match idx {
            3 | 5 | 7 | 9 => {
                uuid_str.push_str(format!("{:02X}", c).as_str());
                uuid_str.push('-');
            }
            _ => {
                uuid_str.push_str(format!("{:02X}", c).as_str());
            }
        }
    }

    macho_file.set_uuid(uuid_str);

    Ok(())
}
```


## New Way
Coming at you live with a slightly changed and refactored parser for `LC_UUID` load commands!

```rust
    /// Parser that parses a LC_UUID command.
    fn uuid_command(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], &'a [u8]> + '_ {
        move |input: &'a [u8]| {
            let (_, uuid) = take(16usize)(input)?;

            Ok((&[], BStr::new(uuid).trim_end_with(|c| c == '\0')))
        }
    }
    
    [...]

    if let Some(uuid) = &m.uuid {
    let mut uuid_str = String::new();

    for (idx, c) in uuid.iter().enumerate() {
        match idx {
            3 | 5 | 7 | 9 => {
                uuid_str.push_str(format!("{:02X}", c).as_str());
                uuid_str.push('-');
            }
            _ => {
                uuid_str.push_str(format!("{:02X}", c).as_str());
            }
        }
    }

    result.uuid = Some(uuid_str.clone());

    [...]
}
```

## Finished Work
This is just part of the work from [#65](https://github.com/VirusTotal/yara-x/pull/65) that I am cleaning up after the refactor. There will be more posts like this :').

I closed [#65](https://github.com/VirusTotal/yara-x/pull/65) as I folded this work into [#78](https://github.com/VirusTotal/yara-x/pull/78).

This specific work implemented today can be seen in [#78](https://github.com/VirusTotal/yara-x/pull/78) on YARA-X.