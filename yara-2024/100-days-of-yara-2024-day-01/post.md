# 100 Days of Yara in 2024: Day 01

y'all like load commands?

## Motivation
As with any feature implementation, I started with a use case. Back in my original [post](https://jacoblatonis.me/posts/yara-and-me) about YARA-X development, I noted about opportunities to cluster binaries based on specific attributes. As I was digging through relevant **Mach-O** `load_commands` for this, I thought the **UUID** load command would be a great starting place. There's a few reasons for my thinking on this being a great starting place: 

1. it is a single field
2. it can be spoofed
3. easy to detect on

With my reasoning laid out above, let's dive into what it takes to implement it.

PS: You may want to have this open if you wish to follow along: 
- [mach-o/loader.h](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h)

## Implementation
In order to implement a newly parsed piece of data in YARA-X, there's a few things we need to implement (this may change as YARA-X matures, but this is what it requires as of 01/01/24).

- define the load command identifier
- define the struct to represent the data from the load command
- function to swap the data from big-endian to little-endian
- function to parse the load command
- update the protobuf representation to contain the new data so it is available to the end user
- function to handle what we do with the parsed data from the load command
- tell the program it can now parse the specific load command implemented
- write tests :)
- update the goldenfiles

This may seem like a fair amount of steps, and the work in each step depends on the complexity of what you are parsing or implementing. This one is fairly straight forward though!

### Defining the Load Command Identifier
This is the easy one. Grab the identifier from the loader header file linked above. In this case, `LC_UUID` is defined like so:

```c
#define LC_UUID		0x1b	/* the uuid */
```

Let's define our `LC_UUID` constant in YARA-X now (I added the leading zeroes for consistency with the rest of the constants in the [file](https://github.com/VirusTotal/yara-x/blob/main/yara-x/src/modules/macho/mod.rs)):

```rust
const LC_UUID: u32 = 0x00000001b;
```

### Defining the Struct
Now that we've defined the indentifier, let's define the struct that will hold our data. This is also a fairly easy one if there's not any nesting or complexities.

Again, we can see from the loader header file that `LC_UUID` is structured like so:

```c
/*
 * The uuid load command contains a single 128-bit unique random number that
 * identifies an object produced by the static link editor.
 */
struct uuid_command {
    uint32_t	cmd;		/* LC_UUID */
    uint32_t	cmdsize;	/* sizeof(struct uuid_command) */
    uint8_t	uuid[16];	/* the 128-bit uuid */
};
```

So, what do we get from this? We see the `cmd` and `cmdsize` fields that every load command has, which lets us identify which `load_command` it is and the size of it. The next field we see is a 16 byte (128 bit) array that holds our UUID. Now that we know what the `load_command` holds, we can define our struct internally.

```rust
/// `UUIDCommand`: Represents a uuid command in the Mach-O file.
/// Fields: cmd, cmdsize, uuid
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct UUIDCommand {
    cmd: u32,
    cmdsize: u32,
    uuid: [u8; 16],
}
```

### Swap that endianness! big-endian to little-endian (if needed)
Depending on which way the bytes flow in the binary, we may need to swap the endianness to allow the parser to parse correctly and as expected. To do so, we can write something like this:

```rust
/// Swaps the endianness of fields within a Mach-O UUID load command from
/// BigEndian to LittleEndian in-place.
///
/// # Arguments
///
/// * `command`: A mutable reference to the Mach-O uuid load command.
fn swap_uuid_command(command: &mut UUIDCommand) {
    command.cmd = BigEndian::read_u32(&command.cmd.to_le_bytes());
    command.cmdsize = BigEndian::read_u32(&command.cmdsize.to_le_bytes());
}
```

### Time to Parse
Now that we've got our struct laid out and ready to hold the data we are gonna parse, let's get to it.

Given the earlier C struct for `LC_UUID`, we know we are going to parse, in this order, a 32bit unsigned integer, another 32bit unsigned integer, and then the 16 byte (128 bit) array of 8 bit chars (unsigned ints if you want to be specific). Thankfully, [nom](https://docs.rs/nom/latest/nom/) makes this trivial.

Our `parse_uuid_command` function will look like this:

```rust
/// Parse a Mach-O UUID load command, transforming raw bytes into a structured
/// format.
///
/// # Arguments
///
/// * `input`: A slice of bytes containing the raw UUIDCommand data.
///
/// # Returns
///
/// A `nom` IResult containing the remaining unparsed input and the parsed
/// UUIDCommand structure, or a `nom` error if the parsing fails.
///
/// # Errors
///
/// Returns a `nom` error if the input data is insufficient or malformed.
fn parse_uuid_command(input: &[u8]) -> IResult<&[u8], UUIDCommand> {
    let (input, cmd) = le_u32(input)?;
    let (input, cmdsize) = le_u32(input)?;
    let (input, uuid) = take(16usize)(input)?;

    Ok((input, UUIDCommand { cmd, cmdsize, uuid: *array_ref![uuid, 0, 16] }))
}
```
### Updating the Protobuf Representation
YARA-X uses the [protobuf](https://docs.rs/protobuf/latest/protobuf/) library to keep track of our data and to eventually allow the end user to query and see the data. In order to expose this newly parsed data to the end user, we need to modify the `macho.proto` file to include the newly parsed info. This one is as simple as adding an additional field on the `macho` protobuf representation.

![git diff showing the addition of the uuid](/static/images/100-days-of-yara-2024-day-01/uuid-proto.png)

### Making use of the Parsed Data
Now that we've parsed the data into our `UUIDCommand` struct and we've modified the protobuf representation, we need to present it to the user. In the code below, we have some bounds checking, some error handling, swapping of bytes for endianness if we need it, and then finally the parsing and filling the appropriate protobuf message. For the UUID, they are normally presented to the user as `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`, and Mach-O files are no different. They also follow the **8-4-4-4-12** standard. In my code below, I iterate over each 8 bits, format it to two characters, append it to the string, and then add dashes where appropriate. After building the UUID string in the proper text representation, I add it to the protobuf message.

```rust
/// Handles the LC_UUID commands for Mach-O files, parsing the data
/// and populating a protobuf representation of the UUID load command.
///
/// # Arguments
///
/// * `command_data`: The raw byte data of the rpath command.
/// * `size`: The size of the UUID load command data.
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
///   smaller than the expected UUIDCommand struct size.
/// * `MachoError::ParsingError`: Returned when there is an error parsing the
///   UUID load command data.
/// * `MachoError::MissingHeaderValue`: Returned when the "magic" header value
///   is missing, needed for determining if bytes should be swapped.
fn handle_uuid_command(
    command_data: &[u8],
    size: usize,
    macho_file: &mut File,
) -> Result<(), MachoError> {
    if size < std::mem::size_of::<UUIDCommand>() {
        return Err(MachoError::FileSectionTooSmall(
            "UUIDCommand".to_string(),
        ));
    }

    let (_, mut uc) = parse_uuid_command(command_data)
        .map_err(|e| MachoError::ParsingError(format!("{:?}", e)))?;
    if should_swap_bytes(
        macho_file
            .magic
            .ok_or(MachoError::MissingHeaderValue("magic".to_string()))?,
    ) {
        swap_uuid_command(&mut uc);
    }

    let mut uuid_str = String::new();

    for (idx, c) in uc.uuid.iter().enumerate() {
        match idx {
            3 | 5 | 7 | 9 => {
                uuid_str.push_str(format!("{:02X}", c).as_str());
                uuid_str.push('-');
            }
            _ => {
                uuid_str.push_str(format!("{:02X}", c).as_str());
            }
        }
    }

    macho_file.set_uuid(uuid_str);

    Ok(())
}
```

### Telling YARA-X to parse the Newly Implemented Load Command
This one is fairly straight forward. Remember how we declared `LC_UUID` at the start? We can now use that constant to trigger the `handle_uuid_command` and `parse_uuid_command` functions and get that data to the end user. In our case, this is adding the `LC_UUID` command to the `match` statement and having it call the `handle_uuid_command` function like so.

```rust
LC_UUID => {
    handle_uuid_command(command_data, cmdsize, macho_file)?;
}
```

### Writing the Tests
Please write tests :) 

Testing is covered in a few ways here. We should test our `swap_uuid_command()` function like so:

```rust
#[test]
fn test_swap_uuid_command() {
    let mut command: UUIDCommand = UUIDCommand { cmd: 0x11223344, cmdsize: 0x55667788, uuid: [0; 16]};

    swap_uuid_command(&mut command);

    assert_eq!(command.cmd, 0x44332211);
    assert_eq!(command.cmdsize, 0x88776655);
}
```

Finally, we run `cargo test` to run all of the test cases and ensure nothing broke. If this is your first time running it before updating the goldenfiles, you'll see an error saying the old goldenfile does not match the new goldenfile. This is expected because (hopefully) you're parsing new data and adding it to the goldenfile! If things changed other than your data being parsed, odds are you parsed some extra data (or maybe not enough).

### Updating the Goldenfiles

After viewing the goldenfiles and ensuring your testing was successful, you can run `UPDATE_GOLDENFILES=1 cargo test` to update the goldenfiles and run the tests again.

![goldenfile diff](/static/images/100-days-of-yara-2024-day-01/goldenfile.png)

## Finished Result
Now, after all that, we can find the pull request for this work at [#65](https://github.com/VirusTotal/yara-x/pull/65) on the YARA-X repo.

### Writing a YARA Rule
Data? Parsed. Rule? Not written! 

Here's a YARA rule that our new Macho-O feature implementation allows us to write:

```
import "macho"

rule MachoUUID {
    condition:
		for any file in macho.file : (
			file.uuid == "0443555D-A992-3B9E-8BCE-5D9FC8BAC0E9"
		)
}
```

and boom! it matches

![terminal screenshot showing the yara rule matching](/static/images/100-days-of-yara-2024-day-01/confirm.png)