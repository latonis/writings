# 100 Days of Yara in 2024: Day 29
In [Day 28](https://jacoblatonis.me/posts/100-days-of-yara-2024-day-28), I mentioned the parsing and structure of the module changed a fair amount. As such, I wanted to show folks how that parsing may have changed when looking at old structure versus the new structure. I have some old work that needs to be reworked into the new format, so I have a perfect example to show!

## Original Way
When parsing the `LC_CODE_SIGNATURE` data from Mach-o binaries, I had written it for the old way. Let's take a look at what that looks like in Rust:

```rust
struct LinkedItDataCommand {
    cmd: u32,
    cmdsize: u32,
    dataoff: u32,
    datasize: u32,
}

fn parse_linkedit_data_command(
    input: &[u8],
) -> IResult<&[u8], LinkedItDataCommand> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;
    let (input, dataoff) = le_u32(input)?;
    let (input, datasize) = le_u32(input)?;

    Ok((input, LinkedItDataCommand { cmd, cmdsize, dataoff, datasize }))
}

fn handle_linkedit_data_command(
    command_data: &[u8],
    size: usize,
    macho_file: &mut File,
) -> Result<(), MachoError> {
    if size < std::mem::size_of::<LinkedItDataCommand>() {
        return Err(MachoError::FileSectionTooSmall(
            "LinkedItDataCommand".to_string(),
        ));
    }

    let (_, mut lid) = parse_linkedit_data_command(command_data)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;

    if should_swap_bytes(
        macho_file
            .magic
            .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
    ) {
        swap_linkedit_data_command(&mut lid);
    };

    // TODO: handle the other ones mentioned in the header
    if lid.cmd == LC_CODE_SIGNATURE {
        macho_file.code_signature_data = MessageField::some(LinkedItData {
            cmd: Some(lid.cmd),
            cmdsize: Some(lid.cmdsize),
            dataoff: Some(lid.dataoff),
            datasize: Some(lid.datasize),
            ..Default::default()
        });
    }

    Ok(())
}

fn swap_linkedit_data_command(command: &mut LinkedItDataCommand) {
    command.cmd = BigEndian::read_u32(&command.cmd.to_le_bytes());
    command.cmdsize = BigEndian::read_u32(&command.cmdsize.to_le_bytes());
    command.dataoff = BigEndian::read_u32(&command.dataoff.to_le_bytes());
    command.datasize = BigEndian::read_u32(&command.datasize.to_le_bytes());
}
```

You can see above, we have a parsing function, a handling function, a swap function for endianness, and then the struct for LinkedItData load commands.

## New Way
The new way is quite clean and accounts for endianness upon parsing, and is a fair bit cleaner. We rely on Nom's combinator functions to map data to fields when parsing. It also uses closures and move to capture data efficiently and store it for later when we populate protobufs. You'll notice there's no need for swapping now either, as endianess is taken into account when parsing.

```rust
    /// Parser that parses a LC_CODESIGNATURE command
    fn linkeditdata_command(&self,) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], LinkedItData> + '_ {
        map(
            tuple((
                u32(self.endianness), //  dataoff
                u32(self.endianness), //  datasize
            )),
            |(
                dataoff,
                datasize,
            )| {
                LinkedItData {
                    dataoff,
                    datasize,
                }
            },
        )
    }

struct LinkedItData {
    dataoff: u32,
    datasize: u32,
}

impl From<&LinkedItData> for protos::macho::LinkedItData {
    fn from(lid: &LinkedItData) -> Self {
        let mut result = protos::macho::LinkedItData::new();
        result.set_dataoff(lid.dataoff);
        result.set_datasize(lid.datasize);
        result
    }
}
```

## Finished Work
I have quite a few older PRs that need to be combined and reworked given the new format. I plan on converting all of these and ensuring everything works as expected still. I just wanted to give a quick example on how data is parsed and moved around now, as it is quite different.

This specific work can be seen at [#78](https://github.com/VirusTotal/yara-x/pull/78) on YARA-X.