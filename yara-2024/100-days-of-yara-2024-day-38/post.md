# 100 Days of Yara in 2024: Day 38
Following the theme of the last few days of my [#100DaysofYARA](https://twitter.com/hashtag/100DaysofYARA?src=hashtag_click) posts, I am once again refactoring a portion of a PR to follow the new parsing format and methodology for the Mach-O module and YARA-X. If you remember way back in [Day 08](https://jacoblatonis.me/posts/100-days-of-yara-2024-day-08), I parsed out the `LC_BUILD_VERSION` load command. Unfortunately, it now needs to be refactored as the PR ([#68](https://github.com/VirusTotal/yara-x/pull/68)) wasn't merged in before the refactor. As such, we have some work to do!

## Original Way
The old way involves the endianness swapping, a handler function, and a parsing function for both the build version data and the build too objects.

```rust
const LC_BUILD_VERSION: u32 = 0x00000032;

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

/// Swaps the endianness of fields within a Mach-O BuildVersionCommand command from
/// BigEndian to LittleEndian in-place.
///
/// # Arguments
///
/// * `command`: A mutable reference to the Mach-O build version command.
fn swap_build_version_command(command: &mut BuildVersionCommand) {
    command.cmd = BigEndian::read_u32(&command.cmd.to_le_bytes());
    command.cmdsize = BigEndian::read_u32(&command.cmdsize.to_le_bytes());
    command.platform = BigEndian::read_u32(&command.platform.to_le_bytes());
    command.minos = BigEndian::read_u32(&command.minos.to_le_bytes());
    command.sdk = BigEndian::read_u32(&command.sdk.to_le_bytes());
    command.ntools = BigEndian::read_u32(&command.ntools.to_le_bytes());
}

/// Swaps the endianness of fields within a Mach-O BuildTool struct from
/// BigEndian to LittleEndian in-place.
///
/// # Arguments
///
/// * `command`: A mutable reference to the Mach-O build tool struct.
fn swap_build_tool(command: &mut BuildToolObject) {
    command.tool = BigEndian::read_u32(&command.tool.to_le_bytes());
    command.version = BigEndian::read_u32(&command.version.to_le_bytes());
}


/// Parse a Mach-O BuildVersionCommand, transforming raw bytes into a structured
/// format.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw BuildVersionCommand data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining unparsed input and the parsed
/// BuildVersionCommand structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
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

/// Parse a Mach-O BuiltTool struct, transforming raw bytes into a structured
/// format.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw BuildToolObject data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining unparsed input and the parsed
/// BuildToolObject structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_build_tool(input: &[u8]) -> IResult<&[u8], BuildToolObject> {
    let (input, tool) = le_u32(input)?;
    let (input, version) = le_u32(input)?;

    Ok((input, BuildToolObject { tool, version }))
}

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


## New Way
Coming at you live with a slightly changed and refactored parser for the `LC_BUILD_VERSION` load command and the associated build tools structs!

```rust
    /// Parser that parses a LC_BUILD_VERSION command.
    fn build_version_command(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], BuildVersionCommand> + '_
    {
        move |input: &'a [u8]| {
            let (mut remainder, (platform, minos, sdk, ntools)) =
                tuple((
                    u32(self.endianness), // platform,
                    u32(self.endianness), // minos,
                    u32(self.endianness), // sdk,
                    u32(self.endianness), // ntools,
                ))(input)?;

            let mut tools = Vec::<BuildToolObject>::new();

            for _ in 0..ntools {
                let (data, (tool, version)) = tuple((
                    u32(self.endianness), // tool,
                    u32(self.endianness), // version,
                ))(remainder)?;

                remainder = data;

                tools.push(BuildToolObject { tool, version })
            }

            Ok((
                &[],
                BuildVersionCommand { platform, minos, sdk, ntools, tools },
            ))
        }
    }

    [...]
    
    if let Some(bv) = &macho.build_version {
        result.build_version = MessageField::some(bv.into());
    }

    [...]
    
    impl From<&BuildVersionCommand> for protos::macho::BuildVersion {
    fn from(bv: &BuildVersionCommand) -> Self {
        let mut result = protos::macho::BuildVersion::new();
        result.set_platform(bv.platform);
        result.set_ntools(bv.ntools);
        result.set_minos(convert_to_version_string(bv.minos));
        result.set_sdk(convert_to_version_string(bv.sdk));
        result.tools.extend(bv.tools.iter().map(|tool| tool.into()));
        result
        }
    }

    impl From<&BuildToolObject> for protos::macho::BuildTool {
        fn from(bt: &BuildToolObject) -> Self {
            let mut result = protos::macho::BuildTool::new();
            result.set_tool(bt.tool);
            result.set_version(convert_to_build_tool_version(bt.version));
            result
        }
    }
```

## Finished Work
This is just part of the work from [#68](https://github.com/VirusTotal/yara-x/pull/68) that I am cleaning up after the refactor. There will be more posts like this :').

I closed [#68](https://github.com/VirusTotal/yara-x/pull/68) as I folded this work into [#78](https://github.com/VirusTotal/yara-x/pull/78).

This specific work implemented today can be seen in [#78](https://github.com/VirusTotal/yara-x/pull/78) on YARA-X.