# 100 Days of Yara in 2024: Day 13
Even more load commands!! Yesterday, we began the ground work for parsing symbol tables in Mach-O binaries by parsing `LC_DYSYMTAB` structures to get the information for the offsets and metadata for the dynamic linker symbol tables. Today, we're doing more groundwork and parsing `LC_SYMTAB` structures.

## The Data Layout
Again, we are going to use our trusty [`loader.h`](https://opensource.apple.com/source/xnu/xnu-4570.1.46/EXTERNAL_HEADERS/mach-o/loader.h.auto.html) file for Mach-O binaries. It indentifies the structure for the load command as such:

```c
/*
 * The symtab_command contains the offsets and sizes of the link-edit 4.3BSD
 * "stab" style symbol table information as described in the header files
 * <nlist.h> and <stab.h>.
 */
struct symtab_command {
	uint32_t	cmd;		/* LC_SYMTAB */
	uint32_t	cmdsize;	/* sizeof(struct symtab_command) */
	uint32_t	symoff;		/* symbol table offset */
	uint32_t	nsyms;		/* number of symbol table entries */
	uint32_t	stroff;		/* string table offset */
	uint32_t	strsize;	/* string table size in bytes */
};
```

I mapped the dynamic symbol table data out into the following structure in Rust:

```rust
/// `SymtabCommand`: Represents a symbol table load command in the Mach-O file.
/// Fields: cmd, cmdsize, symoff, nsyms, stroff, strsize
///
struct SymtabCommand {
    cmd: u32,
    cmdsize: u32,
    symoff: u32,
    nsyms: u32,
    stroff: u32,
    strsize: u32,
}
```

## Parsing the Data
Parsing for the dynamic symbol table is easy, less fields than the Dysymtab command, and still all u32 ints.

### Handling Function
The handling function involves some error checking, invoking the parsing function, and setting the relevant details in the protobuf representation.

```rust
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

### Parsing Function
The parsing function will be called by the handling function above. We have a single parsing function defined:

```rust
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
```

## End Result
Our current test binaries have the symbol table information ready to parse, and we can see the output after running the tests and updating the golden files for output comparison.
```
[...]

    symtab:
        cmd: 2
        cmdsize: 24
        symoff: 8344
        nsyms: 6
        stroff: 8440
        strsize: 72

[...]
```

## Finished Work

I created a new PR to YARA-X here: [#73](https://github.com/VirusTotal/yara-x/pull/73) :)

With this data parsed, we can build and view all of the symbols in a later PR for both Dysymtab and Symtab.