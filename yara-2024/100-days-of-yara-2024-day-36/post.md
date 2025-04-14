# 100 Days of Yara in 2024: Day 36
Yesterday in [Day 35](https://jacoblatonis.me/posts/100-days-of-yara-2024-day-35), I refactored the LC_SYMTAB parsing to fit with the new parser implementation. Now, we can parse the symbol table entries again but refactor it a little bit to be more efficient.

## Original Way
This was was a little less performant due to allocating new Strings and then copying those over.

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

Admittedly, this one doesn't change all that much, except for where the strings are parsed in the execution of the code and that we don't convert them to String anymore, we store the actual bytes and use the reference to those instead of creating new Strings. This adds some Rust lifetime stuff I had to work through, but it worked out!

## New Way
Coming at you live with a slightly changed and refactored symtab load command parser!!

```rust
        if let Some(ref mut symtab) = macho.symtab {
            let str_offset = symtab.stroff as usize;
            let str_end = symtab.strsize as usize;

            // We don't want the dyld_shared_cache ones for now
            if str_offset < data.len() {
                let string_table: &[u8] =
                    &data[str_offset..str_offset + str_end];
                let strings: Vec<&'a [u8]> = string_table
                    .split(|&c| c == b'\0')
                    .map(|line| BStr::new(line).trim_end_with(|c| c == '\0'))
                    .filter(|s| !s.trim().is_empty())
                    .collect();

                symtab.entries.extend(strings);
            }
        }
```

## Finished Work
This is just part of the work from [#73](https://github.com/VirusTotal/yara-x/pull/73) that I am cleaning up after the refactor. There will be more posts like this :').

This specific work implemented today can be seen in [#78](https://github.com/VirusTotal/yara-x/pull/78) on YARA-X.