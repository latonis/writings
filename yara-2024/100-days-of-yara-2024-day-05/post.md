# 100 Days of Yara in 2024: Day 05
Well this topic one isn't really super fun, but it is a super important one: debugging strange findings.

## What Happened
I wrote some code that had a bug in it, didn't realize it until recently. Important part, it is fixed and it is part of the process!

## Parsing RPaths and Dylibs
A little while ago (PR [#46](https://github.com/VirusTotal/yara-x/pull/46)) that attempted to parse RPath load commands from a Mach-O header.

Before I break down the bug, I want to post the offending code and see if anyone can spot it:

### Buggy Code
```rust
fn handle_rpath_command(
    command_data: &[u8],
    size: usize,
    macho_file: &mut File,
) -> Result<(), MachoError> {
    if size < std::mem::size_of::<RPathCommand>() {
        return Err(MachoError::FileSectionTooSmall(
            "RPathCommand".to_string(),
        ));
    }

    let (_, mut rp) = parse_rpath_command(command_data)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;
    if should_swap_bytes(
        macho_file
            .magic
            .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
    ) {
        swap_rpath_command(&mut rp);
    }

    let rpath = RPath {
        cmd: Some(rp.cmd),
        cmdsize: Some(rp.cmdsize),
        path: Some(
            std::str::from_utf8(&rp.path)
                .unwrap_or_default()
                .trim_end_matches('\0')
                .to_string(),
        ),
        ..Default::default()
    };
    macho_file.rpaths.push(rpath);
    Ok(())
}
```

```rust
fn parse_rpath_command(input: &[u8]) -> IResult<&[u8], RPathCommand> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;
    let (input, offset) = le_u32(input)?;
    let (input, path) = take(cmdsize - offset)(input)?;

    Ok((input, RPathCommand { cmd, cmdsize, path: path.into() }))
}
```

I didn't notice this bug for a little while, but I am glad to have found it and fixed it. The code currently will parse each value based on offsets provided in the load command itself. This code will work for Big-Endian files, but it will not parse the offset properly for Little-Endian files. Can you see why?

The swapping and accounting for endianness occurs *after* the parsing. Leaving it like this, the offset will likely be a very large number in Little-Endian files and cause things to not parse properly.

### Fixed Code

```rust
fn swap_rpath_command(command: &mut RPathCommand) {
    command.cmd = BigEndian::read_u32(&command.cmd.to_le_bytes());
    command.cmdsize = BigEndian::read_u32(&command.cmdsize.to_le_bytes());
    command.offset = BigEndian::read_u32(&command.offset.to_le_bytes());
}

fn parse_rpath_command(
    input: &[u8],
    swap: bool,
) -> IResult<&[u8], RPathCommand> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;
    let (input, offset) = le_u32(input)?;

    let mut rp = RPathCommand { cmd, cmdsize, offset, ..Default::default() };

    if swap {
        swap_rpath_command(&mut rp);
    }

    let (input, path) = take(rp.cmdsize - rp.offset)(input)?;

    rp.path = path.into();

    Ok((input, rp))
}
```

```rust
fn handle_rpath_command(
    command_data: &[u8],
    size: usize,
    macho_file: &mut File,
) -> Result<(), MachoError> {
    // 4 bytes for cmd, 4 bytes for cmdsize, 4 bytes for offset
    // fat pointer of vec makes for inaccurate count
    if size < 12 {
        return Err(MachoError::FileSectionTooSmall(
            "RPathCommand".to_string(),
        ));
    }

    let swap = should_swap_bytes(
        macho_file
            .magic
            .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
    );

    let (_, rp) = parse_rpath_command(command_data, swap)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;

    let rpath = RPath {
        cmd: Some(rp.cmd),
        cmdsize: Some(rp.cmdsize),
        path: Some(
            std::str::from_utf8(&rp.path)
                .unwrap_or_default()
                .trim_end_matches('\0')
                .to_string(),
        ),
        ..Default::default()
    };
    macho_file.rpaths.push(rpath);
    Ok(())
}
```

With this new code, we account for endianness *before* taking the offset and doing the calculations for the strings.
This bug also affected Dylib parsing and was subsequently fixed.

## Summary
I think it is important to acknowledge bugs and the process to fix them. As I mentioned before in regard to maintenance and chores, it applies here too: software engineering is not always new features and fast moving development. Sometimes it requires a bit of time to slow down and see where things went wrong :).

## Finished Product
I fixed this bug in PR [#67](https://github.com/VirusTotal/yara-x/pull/67). :)