# 100 Days of Yara in 2024: Day 14
[Day 12](https://jacoblatonis.me/posts/100-days-of-yara-2024-day-12) and [Day 13](https://jacoblatonis.me/posts/100-days-of-yara-2024-day-13) focused on parsing `LC_DYSYMTAB` and `LC_SYMTAB` load commands so we could get the data needed to perform the offset calculations to parse the symbol tables and the string tables in Mach-O binaries. Now that those are being parsed, we can focus on parsing the string table today.

When looking at a hex dump of a Mach-O binary, you may notice there are a few blobs of strings in there. The one we're focused on parsing today are a designated area defined by `LC_SYMTAB`. 

![portion of a hex dump of a Mach-O binary](/static/images/100-days-of-yara-2024-day-14/hexdump.png).

This is not the same as the `__cstring` section, we'll parse that later.

## The Data Layout
The data layout of the string table designated by `LC_SYMTAB` is a blob of strings that are separated by a null byte (`b'\0'`)

## Parsing the Data
To parse this data, we need to go to the offset designated by `LC_SYMTAB.stroff` and parse until we've reached the size of the blob, designated by `LC_SYMTAB.strsize`. Then, we can build a vector of strings and place it in the protobuf representation. At times, the value of `stroff` will be larger than the entire size of the file, this indicates it is not located in the Mach-O, but is located in `dyld_shared_cache`. We'll parse those another time.

### Parsing Function
The parsing function is defined as below, we read the data in, select the string blob, split by `b'\0'`, and then build strings from the raw bytes.

```rust
/// Processes the symbol table and string table based on the values calculated
/// from the LC_SYMTAB load command.
///
/// # Arguments
///
/// * `data`: The raw byte data of the Mach-O file.
/// * `macho_file`: The protobuf representation of the Mach-O file to be populated.
///
/// # Returns
///
/// Returns a `Result<(), MachoError>` indicating the success or failure of the
/// parsing operation.
fn parse_macho_symtab_tables(
    data: &[u8],
    macho_file: &mut File,
) -> Result<(), MachoError> {
    if macho_file.symtab.is_some() {
        let symtab = macho_file.symtab.as_mut().unwrap();

        let str_offset = symtab.stroff() as usize;
        let str_end = symtab.strsize() as usize;
        // We don't want the dyld_shared_cache ones for now
        if str_offset < data.len() {
            let string_table: &[u8] = &data[str_offset..str_offset + str_end];
            let strings: Vec<String> = string_table
                .split(|&c| c == b'\0')
                .map(|line| {
                    std::str::from_utf8(line)
                        .unwrap_or_default()
                        .trim_end_matches('\0')
                        .to_string()
                })
                .filter(|s| !s.trim().is_empty())
                .collect();

            symtab.strings = strings;
        }
    }

    Ok(())
}
```

## End Result
Our current test binaries now show the parsed strings from the string tabled defined by `LC_SYMTAB`.
```
[...]

    symtab:
    
    [...]

        strings:
        - "_harmony_calloc"
        - "_harmony_free"
        - "_harmony_malloc"
        - "_memset"
        - "_strcpy"
        - "_strlen"
        - "_wcslen"
        - "_wxConvUTF8Ptr"
        - "_wxEmptyString"
        - "_wxTheAssertHandler"
        - "_wxTrapInAssert"
        - "dyld_stub_binder"
        - "___clang_call_terminate"

[...]
```

## Finished Work

I added this work to the PR to YARA-X here: [#73](https://github.com/VirusTotal/yara-x/pull/73) :)