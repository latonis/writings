# 100 Days of Yara in 2024: Day 34
Following the theme of the last few days of my [#100DaysofYARA](https://twitter.com/hashtag/100DaysofYARA?src=hashtag_click) posts, I am once again refactoring a portion of a PR to follow the new parsing format and methodology for the Mach-O module and YARA-X.

## Original Way
We need to refactor the code I wrote that parses LC_DYLD_INFO and LC_DYLD_INFO_ONLY load commands.

```rust
/// `DyldInfoCommand`: Represents the dyld info load command in the Mach-O file.
/// Fields: cmd, cmdsize, rebase_off, rebase_size, bind_off, bind_size, weak_bind_off
/// weak_bind_size, lazy_bind_off, lazy_bind_size, export_off, export_size
#[derive(Debug, Default, Clone, Copy)]
struct DyldInfoCommand {
    cmd: u32,
    cmdsize: u32,
    rebase_off: u32,
    rebase_size: u32,
    bind_off: u32,
    bind_size: u32,
    weak_bind_off: u32,
    weak_bind_size: u32,
    lazy_bind_off: u32,
    lazy_bind_size: u32,
    export_off: u32,
    export_size: u32,
}

/// Swaps the endianness of fields within a Mach-O dyld info command from
/// BigEndian to LittleEndian in-place.
///
/// # Arguments
///
/// * `command`: A mutable reference to the Mach-O dyld info command.
fn swap_dyld_info_command(command: &mut DyldInfoCommand) {
    command.cmd = BigEndian::read_u32(&command.cmd.to_le_bytes());
    command.cmdsize = BigEndian::read_u32(&command.cmdsize.to_le_bytes());
    command.rebase_off =
        BigEndian::read_u32(&command.rebase_off.to_le_bytes());
    command.rebase_size =
        BigEndian::read_u32(&command.rebase_size.to_le_bytes());
    command.bind_off = BigEndian::read_u32(&command.bind_off.to_le_bytes());
    command.bind_size = BigEndian::read_u32(&command.bind_size.to_le_bytes());
    command.weak_bind_off =
        BigEndian::read_u32(&command.weak_bind_off.to_le_bytes());
    command.weak_bind_size =
        BigEndian::read_u32(&command.weak_bind_size.to_le_bytes());
    command.lazy_bind_off =
        BigEndian::read_u32(&command.lazy_bind_off.to_le_bytes());
    command.lazy_bind_size =
        BigEndian::read_u32(&command.lazy_bind_size.to_le_bytes());
    command.export_off =
        BigEndian::read_u32(&command.export_off.to_le_bytes());
    command.export_size =
        BigEndian::read_u32(&command.export_size.to_le_bytes());
}

/// Parse a Mach-O DyldInfoCommand, transforming raw bytes into a
/// structured format.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw DyldInfoCommand data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining unparsed input and the parsed
/// DyldInfoCommand structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_dyld_info_command(input: &[u8]) -> IResult<&[u8], DyldInfoCommand> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;
    let (input, rebase_off) = le_u32(input)?;
    let (input, rebase_size) = le_u32(input)?;
    let (input, bind_off) = le_u32(input)?;
    let (input, bind_size) = le_u32(input)?;
    let (input, weak_bind_off) = le_u32(input)?;
    let (input, weak_bind_size) = le_u32(input)?;
    let (input, lazy_bind_off) = le_u32(input)?;
    let (input, lazy_bind_size) = le_u32(input)?;
    let (input, export_off) = le_u32(input)?;
    let (input, export_size) = le_u32(input)?;

    Ok((
        input,
        DyldInfoCommand {
            cmd,
            cmdsize,
            rebase_off,
            rebase_size,
            bind_off,
            bind_size,
            weak_bind_off,
            weak_bind_size,
            lazy_bind_off,
            lazy_bind_size,
            export_off,
            export_size,
        },
    ))
}

/// Handles the LC_DYLD_INFO_ONLY and LC_DYLD_INFO commands for Mach-O files,
/// parsing the data and populating a protobuf representation of the dyld info command.
///
/// # Arguments
///
/// * `command_data`: The raw byte data of the dyld info command.
/// * `size`: The size of the dyld info command data.
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
///   smaller than the expected DyldInfoCommand struct size.
/// * `MachoError::ParsingError`: Returned when there is an error parsing the
///   dyld info command data.
/// * `MachoError::MissingHeaderValue`: Returned when the "magic" header value
///   is missing, needed for determining if bytes should be swapped.
fn handle_dyld_info_command(
    command_data: &[u8],
    size: usize,
    macho_file: &mut File,
) -> Result<(), MachoError> {
    if size < std::mem::size_of::<DyldInfoCommand>() {
        return Err(MachoError::FileSectionTooSmall(
            "DyldInfoCommand".to_string(),
        ));
    }

    let (_, mut dyl) = parse_dyld_info_command(command_data)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;

    if should_swap_bytes(
        macho_file
            .magic
            .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
    ) {
        swap_dyld_info_command(&mut dyl);
    };

    macho_file.dyld_info = MessageField::some(DyldInfo {
        cmd: Some(dyl.cmd),
        cmdsize: Some(dyl.cmdsize),
        rebase_off: Some(dyl.rebase_off),
        rebase_size: Some(dyl.rebase_size),
        bind_off: Some(dyl.bind_off),
        bind_size: Some(dyl.bind_size),
        weak_bind_off: Some(dyl.weak_bind_off),
        weak_bind_size: Some(dyl.weak_bind_size),
        lazy_bind_off: Some(dyl.lazy_bind_off),
        lazy_bind_size: Some(dyl.lazy_bind_size),
        export_off: Some(dyl.export_off),
        export_size: Some(dyl.export_size),
        ..Default::default()
    });

    Ok(())
}
```

This one doesn't change all that much, except for now there's no swapping needed for endianness.

## New Way
The new way implements a function on the Mach-O parser and looks pretty clean comparatively, a lot less to juggle when developing.

```rust
    /// Parser that parses LC_DYLD_INFO_ONLY and LC_DYLD_INFO commands
    fn dyld_info_command(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], DyldInfo> + '_ {
        map(
            tuple((
                u32(self.endianness), //  rebase_off
                u32(self.endianness), //  rebase_size
                u32(self.endianness), //  bind_off
                u32(self.endianness), //  bind_size
                u32(self.endianness), //  weak_bind_off
                u32(self.endianness), //  weak_bind_size
                u32(self.endianness), //  lazy_bind_off
                u32(self.endianness), //  lazy_bind_size
                u32(self.endianness), //  export_off
                u32(self.endianness), //  export_size
            )),
            |(
                rebase_off,
                rebase_size,
                bind_off,
                bind_size,
                weak_bind_off,
                weak_bind_size,
                lazy_bind_off,
                lazy_bind_size,
                export_off,
                export_size,
            )| {
                DyldInfo {
                    rebase_off,
                    rebase_size,
                    bind_off,
                    bind_size,
                    weak_bind_off,
                    weak_bind_size,
                    lazy_bind_off,
                    lazy_bind_size,
                    export_off,
                    export_size,
                }
            },
        )
    }

    struct DyldInfo {
    rebase_off: u32,
    rebase_size: u32,
    bind_off: u32,
    bind_size: u32,
    weak_bind_off: u32,
    weak_bind_size: u32,
    lazy_bind_off: u32,
    lazy_bind_size: u32,
    export_off: u32,
    export_size: u32,
}
```

## Finished Work
This is just part of the work from [#73](https://github.com/VirusTotal/yara-x/pull/73) that I am cleaning up after the refactor. There will be more posts like this :').

This specific work implemented today can be seen in [#78](https://github.com/VirusTotal/yara-x/pull/78) on YARA-X.