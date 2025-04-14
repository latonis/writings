# 100 Days of Yara in 2024: Day 35
Following the theme of the last few days of my [#100DaysofYARA](https://twitter.com/hashtag/100DaysofYARA?src=hashtag_click) posts, I am once again refactoring a portion of a PR to follow the new parsing format and methodology for the Mach-O module and YARA-X.

## Original Way
We need to refactor the code I wrote that parses the symbol table (LC_SYMTAB) load command.

```rust
/// `SymtabCommand`: Represents a symbol table load command in the Mach-O file.
/// Fields: cmd, cmdsize, symoff, nsyms, stroff, strsize
#[derive(Debug, Default, Clone, Copy)]
struct SymtabCommand {
    cmd: u32,
    cmdsize: u32,
    symoff: u32,
    nsyms: u32,
    stroff: u32,
    strsize: u32,
}

/// Swaps the endianness of fields within a Mach-O SymtabCommand command from
/// BigEndian to LittleEndian in-place.
///
/// # Arguments
///
/// * `command`: A mutable reference to the Mach-O DysymtabCommand command.
fn swap_symtab_command(command: &mut SymtabCommand) {
    command.cmd = BigEndian::read_u32(&command.cmd.to_le_bytes());
    command.cmdsize = BigEndian::read_u32(&command.cmdsize.to_le_bytes());
    command.symoff = BigEndian::read_u32(&command.symoff.to_le_bytes());
    command.nsyms = BigEndian::read_u32(&command.nsyms.to_le_bytes());
    command.stroff = BigEndian::read_u32(&command.stroff.to_le_bytes());
    command.strsize = BigEndian::read_u32(&command.strsize.to_le_bytes());
}

/// Parse a Mach-O SymtabCommand, transforming raw bytes into a structured
/// format.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw SymtabCommand data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining unparsed input and the parsed
/// SymtabCommand structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_symtab_command(input: &[u8]) -> IResult<&[u8], SymtabCommand> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;
    let (input, symoff) = le_u32(input)?;
    let (input, nsyms) = le_u32(input)?;
    let (input, stroff) = le_u32(input)?;
    let (input, strsize) = le_u32(input)?;

    Ok((input, SymtabCommand { cmd, cmdsize, symoff, nsyms, stroff, strsize }))
}

/// Handles the LC_SYMTAB command for Mach-O files, parsing the data
/// and populating a protobuf representation of the symtab command.
///
/// # Arguments
///
/// * `command_data`: The raw byte data of the symtab command.
/// * `size`: The size of the symtab command data.
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
///   smaller than the expected SymtabCommand struct size.
/// * `MachoError::ParsingError`: Returned when there is an error parsing the
///   symtab command data.
/// * `MachoError::MissingHeaderValue`: Returned when the "magic" header value
///   is missing, needed for determining if bytes should be swapped.
fn handle_symtab_command(
    command_data: &[u8],
    size: usize,
    macho_file: &mut File,
) -> Result<(), MachoError> {
    if size < std::mem::size_of::<SymtabCommand>() {
        return Err(MachoError::FileSectionTooSmall(
            "SymtabCommand".to_string(),
        ));
    }

    let (_, mut sym) = parse_symtab_command(command_data)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;

    if should_swap_bytes(
        macho_file
            .magic
            .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
    ) {
        swap_symtab_command(&mut sym);
    };

    macho_file.symtab = MessageField::some(Symtab {
        cmd: Some(sym.cmd),
        cmdsize: Some(sym.cmdsize),
        symoff: Some(sym.symoff),
        nsyms: Some(sym.nsyms),
        stroff: Some(sym.stroff),
        strsize: Some(sym.strsize),
        ..Default::default()
    });

    Ok(())
}
```

This one doesn't change all that much, except for now there's no swapping needed for endianness.

## New Way
Coming at you live with a slightly changed and refactored symtab load command parser!!

```rust
    /// Parser that parses a LC_DYSYMTAB command.
    fn symtab_command(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], Symtab> + '_ {
        map(
            tuple((
                u32(self.endianness), //  symoff
                u32(self.endianness), //  nsyms
                u32(self.endianness), //  stroff
                u32(self.endianness), //  strsize
            )),
            |(symoff, nsyms, stroff, strsize)| Symtab {
                symoff,
                nsyms,
                stroff,
                strsize,
            },
        )
    }

    struct Symtab {
    symoff: u32,
    nsyms: u32,
    stroff: u32,
    strsize: u32,
}
```

## Finished Work
This is just part of the work from [#73](https://github.com/VirusTotal/yara-x/pull/73) that I am cleaning up after the refactor. There will be more posts like this :').

This specific work implemented today can be seen in [#78](https://github.com/VirusTotal/yara-x/pull/78) on YARA-X.