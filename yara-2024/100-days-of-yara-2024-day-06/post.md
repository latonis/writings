# 100 Days of Yara in 2024: Day 06
Mach-O binaries have the ability to load a dynamic linker and allow the developer to identify it for use with certain load commands. This is yet another piece of data that could likely be used in a detection and in combination with other items in YARA-X to help cluster certain malware or certain threat actors.

## The Data Layout
Again, we are going to use our trusty [`loader.h`](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h) file for Mach-O binaries. It indentifiers 
```c
/*
 * A program that uses a dynamic linker contains a dylinker_command to identify
 * the name of the dynamic linker (LC_LOAD_DYLINKER).  And a dynamic linker
 * contains a dylinker_command to identify the dynamic linker (LC_ID_DYLINKER).
 * A file can have at most one of these.
 * This struct is also used for the LC_DYLD_ENVIRONMENT load command and
 * contains string for dyld to treat like environment variable.
 */
struct dylinker_command {
	uint32_t	cmd;		/* LC_ID_DYLINKER, LC_LOAD_DYLINKER or
					   LC_DYLD_ENVIRONMENT */
	uint32_t	cmdsize;	/* includes pathname string */
	union lc_str    name;		/* dynamic linker's path name */
};
```
## Parsing the Data
This one is very similar to parsing RPath load commands in Mach-O binaries. It involved the load command identifier, the size of the data in the load command (in this case the length of the dynamic linker path name), and the path name itself. Fairly straight forward to parse. However, working through this one is actually what made me realize I had a bug in RPath and Dylib parsing that I wrote about in [Day 05](https://jacoblatonis.me/posts/100-days-of-yara-2024-day-05). Thankfully, I fixed that bug in this PR as well. If you're curious about it, go back and read Day 05 if you haven't already!

### Handling Function
The handling function involves some error checking, invoking the parsing function, and setting the relevant details in the protobuf representation.
```rust
fn handle_dylinker_command(
    command_data: &[u8],
    size: usize,
    macho_file: &mut File,
) -> Result<(), MachoError> {
    // 4 bytes for cmd, 4 bytes for cmdsize, 4 bytes for offset
    // fat pointer of vec makes for inaccurate count
    if size < 12 {
        return Err(MachoError::FileSectionTooSmall(
            "DylinkerCommand".to_string(),
        ));
    }

    let swap = should_swap_bytes(
        macho_file
            .magic
            .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
    );

    let (_, dyl) = parse_dylinker_command(command_data, swap)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;

    macho_file.dynamic_linker = Some(
        std::str::from_utf8(&dyl.name)
            .unwrap_or_default()
            .trim_end_matches('\0')
            .to_string(),
    );
```

### Parsing Function
The parsing function will be called by the handling function above. You can see I account for endianness swapping before the calculations now :).
```rust
fn parse_dylinker_command(
    input: &[u8],
    swap: bool,
) -> IResult<&[u8], DylinkerCommand> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;
    let (input, offset) = le_u32(input)?;

    let mut dyl =
        DylinkerCommand { cmd, cmdsize, offset, ..Default::default() };

    if swap {
        swap_dylinker_command(&mut dyl);
    }

    let (input, name) = take(dyl.cmdsize - dyl.offset)(input)?;

    dyl.name = name.into();

    Ok((input, dyl))
}
```

## End Result
We can now see the dynamic linker paths being parsed in our goldenfiles and testing from this snippet below:
```
[...]

    dylibs:
      - name: "/usr/lib/libSystem.B.dylib"
        timestamp: 2 # 1970-01-01 00:00:02 UTC
        compatibility_version: "1.0.0"
        current_version: "1213.0.0"
    dynamic_linker: "/usr/lib/dyld"
    entry_point: 3808
    stack_size: 0

[...]
```

## Finished Product
You can see this work in PR [#67](https://github.com/VirusTotal/yara-x/pull/67). :)