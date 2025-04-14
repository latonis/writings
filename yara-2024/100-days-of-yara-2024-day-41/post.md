# 100 Days of Yara in 2024: Day 41
I spent a fair amount of today looking into exports in Mach-O binaries. 

#load_command #LC_DYLD_INFO

 

Exports in a Mach-O binary are located at a specific offset found in the `LC_DYLD_INFO(_ONLY)` load command. You may ask, why do we need to parse these if we parse the `LC_SYMTAB` command and get all the symbol table entries there?
 
If a binary is stripped, we can still build the exports from `LC_DYLD_INFO(_ONLY)`, whereas the symbol table will be empty.

We're probably going to throw it back to your uni level computer science classes today. Fair warning.

The `LC_DYLD_INFO(_ONLY)` load command struct is as follows:

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
Note: The comment descriptions for `export_off` and `export_size` are incorrect, they mention `lazy binding` instead of `export`. They should read as 

```c
    uint32_t   export_off;	/* file offset to export info */
    uint32_t   export_size;	/* size of export info */
```

The exports are encoded in a trie in the binary.
- If you're unfamiliar with tries, I recommend checking out https://algs4.cs.princeton.edu/52trie/.

When examining a binary, you can go to the offset to see some string remnants.

The information stored at `export_off` are encoded in a stream of [`uleb128`](https://en.wikipedia.org/wiki/LEB128) bytes, other non-uleb128 bytes, and the nodes of the trie.

Taking a look at a file with exports could look something like this:

![hex output of export symbols](/static/images/100-days-of-yara-2024-day-41/export_hex.png)

If you compare this with the strings read from the symbol table, you would notice that there are bits and pieces of certain strings located in this set of data. This is because the exports are encoded in a trie. 

In the trie, there are nodes, one root (start) node, and then the children which we can use to build the symbols. We will have to walk the trie to build the export symbols properly. This can be accomplished with depth-first searching on the trie to build each symbol.

I'm working on getting this process described formally and having a proof-of-concept codified to share. :)

Stay tuned!

I was able to get the first node parsed with the following code:

```rust
    let (remainder, size) = uleb128()(data)?;

    println!("Terminal Size: {:#02x}", size);

    let (remainder, child_count) = u8(remainder)?;

    println!("Branches: {:#02x}", child_count);

    let (remainder, strr) = map(
        tuple((take_till(|b| b == b'\x00'), tag(b"\x00"))),
        |(s, _)| s,
    )(remainder)?;

    println!("Node Label: {}", BStr::new(strr));

    let (remainder, offset) = uleb128()(remainder)?;
    println!("Node Offset: {:#02x}", offset);
```

The code above allows me to parse out the first node of the trie:

```
Terminal Size: 0x0
Branches: 0x1
Node Label: _
Node Offset: 0x5
```

## Sources Used
-  https://opensource.apple.com/source/xnu/xnu-4570.1.46/EXTERNAL_HEADERS/mach-o/loader.h.auto.html
- https://opensource.apple.com/source/dyld/dyld-852/dyld3/MachOAnalyzer.cpp.auto.html
- https://algs4.cs.princeton.edu/52trie/
