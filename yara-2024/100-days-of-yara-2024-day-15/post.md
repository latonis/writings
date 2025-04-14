# 100 Days of Yara in 2024: Day 15
As we began to parse the symbol tables in [Day 14](https://jacoblatonis.me/posts/100-days-of-yara-2024-day-14), we need some extra information for certain calculations on cached dyld files for later. 

## The Data Layout
Again, we are going to use our trusty [`loader.h`](https://opensource.apple.com/source/xnu/xnu-4570.1.46/EXTERNAL_HEADERS/mach-o/loader.h.auto.html) file for Mach-O binaries. It indentifies the structure for the `DYLD_INFO`` load command as such:

```c
/*
 * The dyld_info_command contains the file offsets and sizes of 
 * the new compressed form of the information dyld needs to 
 * load the image.  This information is used by dyld on Mac OS X
 * 10.6 and later.  All information pointed to by this command
 * is encoded using byte streams, so no endian swapping is needed
 * to interpret it. 
 */
struct dyld_info_command {
   uint32_t   cmd;		/* LC_DYLD_INFO or LC_DYLD_INFO_ONLY */
   uint32_t   cmdsize;		/* sizeof(struct dyld_info_command) */

    /*
     * Dyld rebases an image whenever dyld loads it at an address different
     * from its preferred address.  The rebase information is a stream
     * of byte sized opcodes whose symbolic names start with REBASE_OPCODE_.
     * Conceptually the rebase information is a table of tuples:
     *    <seg-index, seg-offset, type>
     * The opcodes are a compressed way to encode the table by only
     * encoding when a column changes.  In addition simple patterns
     * like "every n'th offset for m times" can be encoded in a few
     * bytes.
     */
    uint32_t   rebase_off;	/* file offset to rebase info  */
    uint32_t   rebase_size;	/* size of rebase info   */
    
    /*
     * Dyld binds an image during the loading process, if the image
     * requires any pointers to be initialized to symbols in other images.  
     * The bind information is a stream of byte sized 
     * opcodes whose symbolic names start with BIND_OPCODE_.
     * Conceptually the bind information is a table of tuples:
     *    <seg-index, seg-offset, type, symbol-library-ordinal, symbol-name, addend>
     * The opcodes are a compressed way to encode the table by only
     * encoding when a column changes.  In addition simple patterns
     * like for runs of pointers initialzed to the same value can be 
     * encoded in a few bytes.
     */
    uint32_t   bind_off;	/* file offset to binding info   */
    uint32_t   bind_size;	/* size of binding info  */
        
    /*
     * Some C++ programs require dyld to unique symbols so that all
     * images in the process use the same copy of some code/data.
     * This step is done after binding. The content of the weak_bind
     * info is an opcode stream like the bind_info.  But it is sorted
     * alphabetically by symbol name.  This enable dyld to walk 
     * all images with weak binding information in order and look
     * for collisions.  If there are no collisions, dyld does
     * no updating.  That means that some fixups are also encoded
     * in the bind_info.  For instance, all calls to "operator new"
     * are first bound to libstdc++.dylib using the information
     * in bind_info.  Then if some image overrides operator new
     * that is detected when the weak_bind information is processed
     * and the call to operator new is then rebound.
     */
    uint32_t   weak_bind_off;	/* file offset to weak binding info   */
    uint32_t   weak_bind_size;  /* size of weak binding info  */
    
    /*
     * Some uses of external symbols do not need to be bound immediately.
     * Instead they can be lazily bound on first use.  The lazy_bind
     * are contains a stream of BIND opcodes to bind all lazy symbols.
     * Normal use is that dyld ignores the lazy_bind section when
     * loading an image.  Instead the static linker arranged for the
     * lazy pointer to initially point to a helper function which 
     * pushes the offset into the lazy_bind area for the symbol
     * needing to be bound, then jumps to dyld which simply adds
     * the offset to lazy_bind_off to get the information on what 
     * to bind.  
     */
    uint32_t   lazy_bind_off;	/* file offset to lazy binding info */
    uint32_t   lazy_bind_size;  /* size of lazy binding infs */
    
    /*
     * The symbols exported by a dylib are encoded in a trie.  This
     * is a compact representation that factors out common prefixes.
     * It also reduces LINKEDIT pages in RAM because it encodes all  
     * information (name, address, flags) in one small, contiguous range.
     * The export area is a stream of nodes.  The first node sequentially
     * is the start node for the trie.  
     *
     * Nodes for a symbol start with a uleb128 that is the length of
     * the exported symbol information for the string so far.
     * If there is no exported symbol, the node starts with a zero byte. 
     * If there is exported info, it follows the length.  
	 *
	 * First is a uleb128 containing flags. Normally, it is followed by
     * a uleb128 encoded offset which is location of the content named
     * by the symbol from the mach_header for the image.  If the flags
     * is EXPORT_SYMBOL_FLAGS_REEXPORT, then following the flags is
     * a uleb128 encoded library ordinal, then a zero terminated
     * UTF8 string.  If the string is zero length, then the symbol
     * is re-export from the specified dylib with the same name.
	 * If the flags is EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER, then following
	 * the flags is two uleb128s: the stub offset and the resolver offset.
	 * The stub is used by non-lazy pointers.  The resolver is used
	 * by lazy pointers and must be called to get the actual address to use.
     *
     * After the optional exported symbol information is a byte of
     * how many edges (0-255) that this node has leaving it, 
     * followed by each edge.
     * Each edge is a zero terminated UTF8 of the addition chars
     * in the symbol, followed by a uleb128 offset for the node that
     * edge points to.
     *  
     */
    uint32_t   export_off;	/* file offset to lazy binding info */
    uint32_t   export_size;	/* size of lazy binding infs */
};
```

I mapped the dyld info data out into the following structure in Rust:

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
```

## Parsing the Data
Parsing the dyld info is very straightforward, just a bunch of `u32` integers to parse and store for future calculations.

### Handling Function
The handling function involves some error checking, invoking the parsing function, and setting the relevant details in the protobuf representation.

```rust
// LC identifiers
const LC_DYLD_INFO: u32 = 0x00000022;
const LC_DYLD_INFO_ONLY: u32 = 0x22 | LC_REQ_DYLD;

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

### Parsing Function
The parsing function will be called by the handling function above. We have a single parsing function defined:

```rust
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
```

## End Result
Our current test binaries have the dyld info structures ready to parse, and we can see the output after running the tests and updating the golden files for output comparison.

```
[...]

    dyld_info:
        cmd: 2147483682
        cmdsize: 48
        rebase_off: 8192
        rebase_size: 16
        bind_off: 8208
        bind_size: 24
        weak_bind_off: 0
        weak_bind_size: 0
        lazy_bind_off: 8232
        lazy_bind_size: 28
        export_off: 8260
        export_size: 60

[...]
```

## Finished Work

I added this work to the PR to YARA-X here: [#73](https://github.com/VirusTotal/yara-x/pull/73) :)
