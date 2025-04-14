# 100 Days of Yara in 2024: Day 08
I have some more load commands to parse! This time, we're covering `LC_BUILD_VERSION` load commands, which are present in multi-architecture Mach-O binaries. They can give us insight into where the binary was intended to run, if its newer or older, and more!


## The Data Layout
Again, we are going to use our trusty [`loader.h`](https://opensource.apple.com/source/xnu/xnu-4570.1.46/EXTERNAL_HEADERS/mach-o/loader.h.auto.html) file for Mach-O binaries. It indentifiers 
```c
/*
 * The build_version_command contains the min OS version on which this
 * binary was built to run for its platform.  The list of known platforms and
 * tool values following it.
 */
struct build_version_command {
    uint32_t	cmd;		/* LC_BUILD_VERSION */
    uint32_t	cmdsize;	/* sizeof(struct build_version_command) plus */
                                /* ntools * sizeof(struct build_tool_version) */
    uint32_t	platform;	/* platform */
    uint32_t	minos;		/* X.Y.Z is encoded in nibbles xxxx.yy.zz */
    uint32_t	sdk;		/* X.Y.Z is encoded in nibbles xxxx.yy.zz */
    uint32_t	ntools;		/* number of tool entries following this */
};

struct build_tool_version {
    uint32_t	tool;		/* enum for the tool */
    uint32_t	version;	/* version number of the tool */
};

/* Known values for the platform field above. */
#define PLATFORM_MACOS 1
#define PLATFORM_IOS 2
#define PLATFORM_TVOS 3
#define PLATFORM_WATCHOS 4

/* Known values for the tool field above. */
#define TOOL_CLANG 1
#define TOOL_SWIFT 2
#define TOOL_LD	3

```

I mapped this data out into the following structures in Rust:
```rust
/// `BuildVersionCommand`: Represents a build version command in the Mach-O file.
/// Fields: cmd, cmdsize, platform, minos, sdk, ntools
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct BuildVersionCommand {
    cmd: u32,
    cmdsize: u32,
    platform: u32,
    minos: u32,
    sdk: u32,
    ntools: u32,
}

/// `BuildToolObject`: Represents a build Tool struct in the Mach-O file following the
/// BuildVersionCommand
/// Fields: tool, version
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct BuildToolObject {
    tool: u32,
    version: u32,
}
```
## Parsing the Data
This one is slightly more complicated to parse than our earlier load commands, as it has the standard struct of `build_version_command`, but we also need to dynamically parse the amount of tools counted by the `build_version_command.ntools` field.


### Handling Function
The handling function involves some error checking, invoking the parsing function, and setting the relevant details in the protobuf representation.
```rust
fn handle_build_version_command(
    command_data: &[u8],
    size: usize,
    macho_file: &mut File,
) -> Result<(), MachoError> {
    if size < std::mem::size_of::<BuildVersionCommand>() {
        return Err(MachoError::FileSectionTooSmall(
            "BuildVersionCommand".to_string(),
        ));
    }

    let swap = should_swap_bytes(
        macho_file
            .magic
            .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
    );

    let (_, mut bc) = parse_build_version_command(command_data)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;

    if swap {
        swap_build_version_command(&mut bc);
    }

    macho_file.build_version = MessageField::some(BuildVersion {
        platform: Some(bc.platform),
        minos: Some(convert_to_version_string(bc.minos)),
        sdk: Some(convert_to_version_string(bc.sdk)),
        ntools: Some(bc.ntools),
        ..Default::default()
    });

    for _n in 0..bc.ntools {
        let (_, mut bt) = parse_build_tool(command_data)
            .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;

        if swap {
            swap_build_tool(&mut bt)
        }

        macho_file.build_tools.push(BuildTool {
            tool: Some(bt.tool),
            version: Some(bt.version),
            ..Default::default()
        });
    }

    Ok(())
}
```

### Parsing Function
The parsing function will be called by the handling function above. We have two parsing functions for the two structs:

```rust
fn parse_build_version_command(
    input: &[u8],
) -> IResult<&[u8], BuildVersionCommand> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;
    let (input, platform) = le_u32(input)?;
    let (input, minos) = le_u32(input)?;
    let (input, sdk) = le_u32(input)?;
    let (input, ntools) = le_u32(input)?;

    Ok((
        input,
        BuildVersionCommand { cmd, cmdsize, platform, minos, sdk, ntools },
    ))
}

fn parse_build_tool(input: &[u8]) -> IResult<&[u8], BuildToolObject> {
    let (input, tool) = le_u32(input)?;
    let (input, version) = le_u32(input)?;

    Ok((input, BuildToolObject { tool, version }))
}
```

## End Result
I had to go on the search for newer testing files for this load command, as all of the current Mach-O tests in YARA-X did not have this load command present. After finding one and converting the binary to the proper format mentioned in [this post](https://jacoblatonis.me/posts/100-days-of-yara-2024-day-07), we can now see the relevant data being parsed in our goldenfiles and testing from this snippet below:
```
[...]

    build_version:
        platform: 1
        minos: "10.15.0"
        sdk: "14.2.0"
        ntools: 1
    build_tools:
      - tool: 50
        version: 32

[...]
```

## Finished Work

I submitted a PR to YARA-X  here: [#68](https://github.com/VirusTotal/yara-x/pull/68) :)