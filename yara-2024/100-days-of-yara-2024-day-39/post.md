# 100 Days of Yara in 2024: Day 39
Following the theme of the last few days of my [#100DaysofYARA](https://twitter.com/hashtag/100DaysofYARA?src=hashtag_click) posts, I am once again refactoring a portion of a PR to follow the new parsing format and methodology for the Mach-O module and YARA-X. If you remember way back in [Day 04](https://jacoblatonis.me/posts/100-days-of-yara-2024-day-04), I parsed out the `LC_VERSION_MIN_*` load commands. Unfortunately, it now needs to be refactored as the PR ([#56](https://github.com/VirusTotal/yara-x/pull/56/files)) wasn't merged in before the refactor. As such, we have some work to do!

## Original Way
The old way involves the endianness swapping, a handler function, and a parsing function for the minimum version load command. There's also a bit of logic to populate the right protobuf structure.

```rust
const LC_VERSION_MIN_MACOSX: u32 = 0x00000024;
const LC_VERSION_MIN_IPHONEOS: u32 = 0x00000025;
const LC_VERSION_MIN_TVOS: u32 = 0x0000002f;
const LC_VERSION_MIN_WATCHOS: u32 = 0x00000030;

/// `MinVersionCommand`: Represents a minimum version command in the Mach-O file.
/// Fields: cmd, cmdsize, version, sdk
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct MinVersionCommand {
    cmd: u32,
    cmdsize: u32,
    version: u32,
    sdk: u32,
}

/// Swaps the endianness of fields within a Mach-O minimum version  
/// command from BigEndian to LittleEndian in-place.
///
/// # Arguments
///
/// * `command`: A mutable reference to the Mach-O minimum version command.
fn swap_min_version_command(command: &mut MinVersionCommand) {
    command.cmd = BigEndian::read_u32(&command.cmd.to_le_bytes());
    command.cmdsize = BigEndian::read_u32(&command.cmdsize.to_le_bytes());
    command.version = BigEndian::read_u32(&command.version.to_le_bytes());
    command.sdk = BigEndian::read_u32(&command.sdk.to_le_bytes());
}

/// Parse a Mach-O MinVersionCommand, transforming raw bytes into a structured
/// format.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw MinVersionCommand data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining unparsed input and the parsed
/// MinVersionCommand structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_min_version_command(
    input: &[u8],
) -> IResult<&[u8], MinVersionCommand> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;
    let (input, version) = le_u32(input)?;
    let (input, sdk) = le_u32(input)?;

    Ok((input, MinVersionCommand { cmd, cmdsize, version, sdk }))
}

/// Handles the LC_VERSION_MIN_MACOSX, LC_VERSION_MIN_IPHONEOS, LC_VERSION_MIN_TVOS, and LC_VERSION_MIN_WATCHOS
/// commands for Mach-O files, parsing the data and populating a protobuf representation of the minimum version
/// load command.
///
/// # Arguments
///
/// * `command_data`: The raw byte data of the minimum version command.
/// * `size`: The size of the minimum version command data.
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
///   smaller than the expected MinVersionCommand struct size.
/// * `MachoError::ParsingError`: Returned when there is an error parsing the
///   minumum version command data.
/// * `MachoError::MissingHeaderValue`: Returned when the "magic" header value
///   is missing, needed for determining if bytes should be swapped.
fn handle_min_version_command(
    command_data: &[u8],
    size: usize,
    macho_file: &mut File,
) -> Result<(), MachoError> {
    if size < std::mem::size_of::<MinVersionCommand>() {
        return Err(MachoError::FileSectionTooSmall(
            "MinVersionCommand".to_string(),
        ));
    }

    let (_, mut mvc) = parse_min_version_command(command_data)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;
    if should_swap_bytes(
        macho_file
            .magic
            .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
    ) {
        swap_min_version_command(&mut mvc);
    }

    // X.Y.Z is encoded in nibbles xxxx.yy.zz
    let ver_string: String = convert_to_version_string(mvc.version);
    // X.Y.Z is encoded in nibbles xxxx.yy.zz
    let sdk_string: String = convert_to_version_string(mvc.sdk);

    match mvc.cmd {
        LC_VERSION_MIN_MACOSX => {
            let min_version_command = MinVersionMacOS {
                cmd: Some(mvc.cmd),
                cmdsize: Some(mvc.cmdsize),
                version: Some(ver_string),
                sdk: Some(sdk_string),
                ..Default::default()
            };

            macho_file.min_version_mac_os =
                MessageField::some(min_version_command);
        }
        LC_VERSION_MIN_IPHONEOS => {
            let min_version_command = MinVersionIphoneOS {
                cmd: Some(mvc.cmd),
                cmdsize: Some(mvc.cmdsize),
                version: Some(ver_string),
                sdk: Some(sdk_string),
                ..Default::default()
            };

            macho_file.min_version_iphone_os =
                MessageField::some(min_version_command);
        }
        LC_VERSION_MIN_TVOS => {
            let min_version_command = MinVersionTvOS {
                cmd: Some(mvc.cmd),
                cmdsize: Some(mvc.cmdsize),
                version: Some(ver_string),
                sdk: Some(sdk_string),
                ..Default::default()
            };

            macho_file.min_version_tv_os =
                MessageField::some(min_version_command);
        }
        LC_VERSION_MIN_WATCHOS => {
            let min_version_command = MinVersionWatchOS {
                cmd: Some(mvc.cmd),
                cmdsize: Some(mvc.cmdsize),
                version: Some(ver_string),
                sdk: Some(sdk_string),
                ..Default::default()
            };

            macho_file.min_version_watch_os =
                MessageField::some(min_version_command);
        }
        _ => {}
    }

    Ok(())
}
```

Originally, I defined four protobuf structures, but I think this can be done with one structure and an enum now.

```
message MinVersionMacOS {
  optional uint32 cmd = 1;
  optional uint32 cmdsize = 2;
  optional string version = 3;
  optional string sdk = 4;
}

message MinVersionIphoneOS {
  optional uint32 cmd = 1;
  optional uint32 cmdsize = 2;
  optional string version = 3;
  optional string sdk = 4;
}

message MinVersionTvOS {
  optional uint32 cmd = 1;
  optional uint32 cmdsize = 2;
  optional string version = 3;
  optional string sdk = 4;
}

message MinVersionWatchOS {
  optional uint32 cmd = 1;
  optional uint32 cmdsize = 2;
  optional string version = 3;
  optional string sdk = 4;
}
```

## New Way
Coming at you live with a slightly changed and refactored parser for the `LC_VERSION_MIN*` load commands. I decided to do an enum in the protobuf for the device type, instead of having four different proto representations.

```
message MinVersion {
  optional uint32 device = 1;
  optional string version = 2;
  optional string sdk = 3;
}

enum DEVICE_TYPE {
  option (yara.enum_options).inline = true;
  MACOSX = 0x00000024;
  IPHONEOS = 0x00000025;
  TVOS = 0x0000002f;
  WATCHOS = 0x00000030;
}
```

```rust
[...]
    LC_VERSION_MIN_MACOSX
    | LC_VERSION_MIN_IPHONEOS
    | LC_VERSION_MIN_TVOS
    | LC_VERSION_MIN_WATCHOS => {
        let (_, mut mv) =
            self.min_version_command()(command_data)?;
        mv.device = command;
        self.min_version = Some(mv);
    }
[...]

    fn min_version_command(
        &self,
    ) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], MinVersion> + '_ {
        move |input: &'a [u8]| {
            let (input, (version, sdk)) = tuple((
                u32(self.endianness), // version
                u32(self.endianness), // sdk,
            ))(input)?;

            Ok((input, MinVersion { device: 0, version, sdk }))
        }
    }

[...]

    struct MinVersion {
        device: u32,
        version: u32,
        sdk: u32,
    }

[...]

    if let Some(bv) = &macho.build_version {
        result.build_version = MessageField::some(bv.into());
    }

[...]

    impl From<&MinVersion> for protos::macho::MinVersion {
        fn from(mv: &MinVersion) -> Self {
            let mut result = protos::macho::MinVersion::new();
            result.set_device(mv.device);
            result.set_version(convert_to_version_string(mv.version));
            result.set_sdk(convert_to_version_string(mv.sdk));
            result
        }
    }

```

## Finished Work
This is just part of the work from [#56](https://github.com/VirusTotal/yara-x/pull/56/files) that I am cleaning up after the refactor. There will be more posts like this :').

I closed [#56](https://github.com/VirusTotal/yara-x/pull/56/files) as I folded this work into [#78](https://github.com/VirusTotal/yara-x/pull/78).

This specific work implemented today can be seen in [#78](https://github.com/VirusTotal/yara-x/pull/78) on YARA-X.