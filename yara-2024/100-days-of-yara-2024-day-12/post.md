# 100 Days of Yara in 2024: Day 12
MOAR LOAD COMMANDS. Hello, we have some more load command parsing, except this one is a bit more in-depth than the previous ones. I decided to start the process for parsing Dysymtab load commands, which is for the symbol table for the dynamic link editor. We're going to parse it today, and then eventually we'll parse out the symbol table itself.


## The Data Layout
Again, we are going to use our trusty [`loader.h`](https://opensource.apple.com/source/xnu/xnu-4570.1.46/EXTERNAL_HEADERS/mach-o/loader.h.auto.html) file for Mach-O binaries. It indentifies the structure for the load command as such:

```c
/*
 * This is the second set of the symbolic information which is used to support
 * the data structures for the dynamically link editor.
 *
 * The original set of symbolic information in the symtab_command which contains
 * the symbol and string tables must also be present when this load command is
 * present.  When this load command is present the symbol table is organized
 * into three groups of symbols:
 *	local symbols (static and debugging symbols) - grouped by module
 *	defined external symbols - grouped by module (sorted by name if not lib)
 *	undefined external symbols (sorted by name if MH_BINDATLOAD is not set,
 *	     			    and in order the were seen by the static
 *				    linker if MH_BINDATLOAD is set)
 * In this load command there are offsets and counts to each of the three groups
 * of symbols.
 *
 * This load command contains a the offsets and sizes of the following new
 * symbolic information tables:
 *	table of contents
 *	module table
 *	reference symbol table
 *	indirect symbol table
 * The first three tables above (the table of contents, module table and
 * reference symbol table) are only present if the file is a dynamically linked
 * shared library.  For executable and object modules, which are files
 * containing only one module, the information that would be in these three
 * tables is determined as follows:
 * 	table of contents - the defined external symbols are sorted by name
 *	module table - the file contains only one module so everything in the
 *		       file is part of the module.
 *	reference symbol table - is the defined and undefined external symbols
 *
 * For dynamically linked shared library files this load command also contains
 * offsets and sizes to the pool of relocation entries for all sections
 * separated into two groups:
 *	external relocation entries
 *	local relocation entries
 * For executable and object modules the relocation entries continue to hang
 * off the section structures.
 */
struct dysymtab_command {
    uint32_t cmd;	/* LC_DYSYMTAB */
    uint32_t cmdsize;	/* sizeof(struct dysymtab_command) */

    /*
     * The symbols indicated by symoff and nsyms of the LC_SYMTAB load command
     * are grouped into the following three groups:
     *    local symbols (further grouped by the module they are from)
     *    defined external symbols (further grouped by the module they are from)
     *    undefined symbols
     *
     * The local symbols are used only for debugging.  The dynamic binding
     * process may have to use them to indicate to the debugger the local
     * symbols for a module that is being bound.
     *
     * The last two groups are used by the dynamic binding process to do the
     * binding (indirectly through the module table and the reference symbol
     * table when this is a dynamically linked shared library file).
     */
    uint32_t ilocalsym;	/* index to local symbols */
    uint32_t nlocalsym;	/* number of local symbols */

    uint32_t iextdefsym;/* index to externally defined symbols */
    uint32_t nextdefsym;/* number of externally defined symbols */

    uint32_t iundefsym;	/* index to undefined symbols */
    uint32_t nundefsym;	/* number of undefined symbols */

    /*
     * For the for the dynamic binding process to find which module a symbol
     * is defined in the table of contents is used (analogous to the ranlib
     * structure in an archive) which maps defined external symbols to modules
     * they are defined in.  This exists only in a dynamically linked shared
     * library file.  For executable and object modules the defined external
     * symbols are sorted by name and is use as the table of contents.
     */
    uint32_t tocoff;	/* file offset to table of contents */
    uint32_t ntoc;	/* number of entries in table of contents */

    /*
     * To support dynamic binding of "modules" (whole object files) the symbol
     * table must reflect the modules that the file was created from.  This is
     * done by having a module table that has indexes and counts into the merged
     * tables for each module.  The module structure that these two entries
     * refer to is described below.  This exists only in a dynamically linked
     * shared library file.  For executable and object modules the file only
     * contains one module so everything in the file belongs to the module.
     */
    uint32_t modtaboff;	/* file offset to module table */
    uint32_t nmodtab;	/* number of module table entries */

    /*
     * To support dynamic module binding the module structure for each module
     * indicates the external references (defined and undefined) each module
     * makes.  For each module there is an offset and a count into the
     * reference symbol table for the symbols that the module references.
     * This exists only in a dynamically linked shared library file.  For
     * executable and object modules the defined external symbols and the
     * undefined external symbols indicates the external references.
     */
    uint32_t extrefsymoff;	/* offset to referenced symbol table */
    uint32_t nextrefsyms;	/* number of referenced symbol table entries */

    /*
     * The sections that contain "symbol pointers" and "routine stubs" have
     * indexes and (implied counts based on the size of the section and fixed
     * size of the entry) into the "indirect symbol" table for each pointer
     * and stub.  For every section of these two types the index into the
     * indirect symbol table is stored in the section header in the field
     * reserved1.  An indirect symbol table entry is simply a 32bit index into
     * the symbol table to the symbol that the pointer or stub is referring to.
     * The indirect symbol table is ordered to match the entries in the section.
     */
    uint32_t indirectsymoff; /* file offset to the indirect symbol table */
    uint32_t nindirectsyms;  /* number of indirect symbol table entries */

    /*
     * To support relocating an individual module in a library file quickly the
     * external relocation entries for each module in the library need to be
     * accessed efficiently.  Since the relocation entries can't be accessed
     * through the section headers for a library file they are separated into
     * groups of local and external entries further grouped by module.  In this
     * case the presents of this load command who's extreloff, nextrel,
     * locreloff and nlocrel fields are non-zero indicates that the relocation
     * entries of non-merged sections are not referenced through the section
     * structures (and the reloff and nreloc fields in the section headers are
     * set to zero).
     *
     * Since the relocation entries are not accessed through the section headers
     * this requires the r_address field to be something other than a section
     * offset to identify the item to be relocated.  In this case r_address is
     * set to the offset from the vmaddr of the first LC_SEGMENT command.
     * For MH_SPLIT_SEGS images r_address is set to the the offset from the
     * vmaddr of the first read-write LC_SEGMENT command.
     *
     * The relocation entries are grouped by module and the module table
     * entries have indexes and counts into them for the group of external
     * relocation entries for that the module.
     *
     * For sections that are merged across modules there must not be any
     * remaining external relocation entries for them (for merged sections
     * remaining relocation entries must be local).
     */
    uint32_t extreloff;	/* offset to external relocation entries */
    uint32_t nextrel;	/* number of external relocation entries */

    /*
     * All the local relocation entries are grouped together (they are not
     * grouped by their module since they are only used if the object is moved
     * from it staticly link edited address).
     */
    uint32_t locreloff;	/* offset to local relocation entries */
    uint32_t nlocrel;	/* number of local relocation entries */

};	
```

I mapped the dynamic symbol table data out into the following structure in Rust:

```rust
/// `DysymtabCommand`: Represents a dynamic symbol table
/// load command in the Mach-O file.
/// Fields: cmd, cmdsize, ilocalsym, nlocalsym, iextdefsym, nextdefsym,
/// tocoff, ntoc, modtaboff, nmodtab, extrefsymoff, nextrefsyms, indirectsymoff,
/// nindirectsyms, extreloff, nextrel, locreloff, nlocrel
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct DysymtabCommand {
    cmd: u32,
    cmdsize: u32,
    ilocalsym: u32,
    nlocalsym: u32,
    iextdefsym: u32,
    nextdefsym: u32,
    tocoff: u32,
    ntoc: u32,
    modtaboff: u32,
    nmodtab: u32,
    extrefsymoff: u32,
    nextrefsyms: u32,
    indirectsymoff: u32,
    nindirectsyms: u32,
    extreloff: u32,
    nextrel: u32,
    locreloff: u32,
    nlocrel: u32,
}
```

## Parsing the Data
Parsing for the dynamic symbol table is easy, there's just a lot of fields to parse, all `u32`.

### Handling Function
The handling function involves some error checking, invoking the parsing function, and setting the relevant details in the protobuf representation.

```rust
fn handle_dysymtab_command(
    command_data: &[u8],
    size: usize,
    macho_file: &mut File,
) -> Result<(), MachoError> {
    if size < std::mem::size_of::<DysymtabCommand>() {
        return Err(MachoError::FileSectionTooSmall(
            "DysymtabCommand".to_string(),
        ));
    }

    let (_, mut dysym) = parse_dysymtab_command(command_data)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;

    if should_swap_bytes(
        macho_file
            .magic
            .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
    ) {
        swap_dysymtab_command(&mut dysym);
    };

    macho_file.dysymtab = MessageField::some(Dysymtab {
        cmd: Some(dysym.cmd),
        cmdsize: Some(dysym.cmdsize),
        ilocalsym: Some(dysym.ilocalsym),
        nlocalsym: Some(dysym.nlocalsym),
        iextdefsym: Some(dysym.iextdefsym),
        nextdefsym: Some(dysym.nextdefsym),
        tocoff: Some(dysym.tocoff),
        ntoc: Some(dysym.ntoc),
        modtaboff: Some(dysym.modtaboff),
        nmodtab: Some(dysym.nmodtab),
        extrefsymoff: Some(dysym.extrefsymoff),
        nextrefsyms: Some(dysym.nextrefsyms),
        indirectsymoff: Some(dysym.indirectsymoff),
        nindirectsyms: Some(dysym.nindirectsyms),
        extreloff: Some(dysym.extreloff),
        nextrel: Some(dysym.nextrel),
        locreloff: Some(dysym.locreloff),
        nlocrel: Some(dysym.nlocrel),
        ..Default::default()
    });

    Ok(())
}
```

### Parsing Function
The parsing function will be called by the handling function above. We have a single parsing function defined:

```rust
fn parse_dysymtab_command(input: &[u8]) -> IResult<&[u8], DysymtabCommand> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;
    let (input, ilocalsym) = le_u32(input)?;
    let (input, nlocalsym) = le_u32(input)?;
    let (input, iextdefsym) = le_u32(input)?;
    let (input, nextdefsym) = le_u32(input)?;
    let (input, tocoff) = le_u32(input)?;
    let (input, ntoc) = le_u32(input)?;
    let (input, modtaboff) = le_u32(input)?;
    let (input, nmodtab) = le_u32(input)?;
    let (input, extrefsymoff) = le_u32(input)?;
    let (input, nextrefsyms) = le_u32(input)?;
    let (input, indirectsymoff) = le_u32(input)?;
    let (input, nindirectsyms) = le_u32(input)?;
    let (input, extreloff) = le_u32(input)?;
    let (input, nextrel) = le_u32(input)?;
    let (input, locreloff) = le_u32(input)?;
    let (input, nlocrel) = le_u32(input)?;

    Ok((
        input,
        DysymtabCommand {
            cmd,
            cmdsize,
            ilocalsym,
            nlocalsym,
            iextdefsym,
            nextdefsym,
            tocoff,
            ntoc,
            modtaboff,
            nmodtab,
            extrefsymoff,
            nextrefsyms,
            indirectsymoff,
            nindirectsyms,
            extreloff,
            nextrel,
            locreloff,
            nlocrel,
        },
    ))
}
```

## End Result
Our current test binaries have the dynamic symbol table information ready to parse, and we can see the output after running the tests and updating the golden files for output comparison.
```
[...]

    dysymtab:
        cmd: 11
        cmdsize: 80
        ilocalsym: 0
        nlocalsym: 0
        iextdefsym: 0
        nextdefsym: 3
        tocoff: 3
        ntoc: 3
        modtaboff: 0
        nmodtab: 0
        extrefsymoff: 0
        nextrefsyms: 0
        indirectsymoff: 0
        nindirectsyms: 0
        extreloff: 8448
        nextrel: 6
        locreloff: 0
        nlocrel: 0

[...]
```

## Finished Work

I added to the PR to YARA-X here: [#67](https://github.com/VirusTotal/yara-x/pull/67) :)

With this data parsed, we can build and view all of the symbols in a later PR.