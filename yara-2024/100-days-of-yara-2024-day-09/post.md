# 100 Days of Yara in 2024: Day 09
With us go over quite a few load commands since Day 01, I decided to try my hand at implementing a function similar to the `pe` module's `import` function, where you can pass it a dll name and it returns true if it is seen in the binary scanned.

Example:
```
pe.imports("kernel32.dll")
```

However, I would like to implement this first for dylib paths, which we already parse.

## The Plan Ahead
We don't have to parse any new data this time around, we just have to implement the function that allows us to search the data we do have parsed already.

## Implementing the Function
Thankfully, YARA-X already has a well developed framework for implementing functions for modules. With the macro `#[module_export(name = "<function_name>")]``
```rust
fn dylibs_present(
    ctx: &ScanContext,
    dylib_name: RuntimeString,
) -> Option<bool> {
    let macho = ctx.module_output::<Macho>()?;
    let expected_name = dylib_name.as_bstr(ctx);

    for dylib in macho.dylibs.iter() {
        if dylib.name.as_ref().is_some_and(|name| {
            expected_name.eq_ignore_ascii_case(name.as_bytes())
        }) {
            return Some(true);
        }
    }

    for file in macho.file.iter() {
        for dylib in file.dylibs.iter() {
            if dylib.name.as_ref().is_some_and(|name| {
                expected_name.eq_ignore_ascii_case(name.as_bytes())
            }) {
                return Some(true);
            }
        }
    }

    Some(false)
}
```

There's probably a more idiomatic way to write this in Rust, and I am sure I will clean it up later. However, for now this works. :)

## End Result
With this newly implemented function, you can now search dylib paths in a YARA rule like so:

```
import "macho"

rule Macho_test {
    condition:
		macho.dylib_present("/usr/lib/libSystem.B.dylib")
}
```

![image showing a command line terminal with a passing yara rule](/static/images/100-days-of-yara-2024-day-09/image.png)

## Tests
I wrote a few tests to validate that the function works as expected:
```rust
    rule_false!(
        r#"
        import "macho"
        rule test {
            condition:
                macho.dylib_present("totally not present dylib")
        }
        "#
    );

    rule_true!(
        r#"
        import "macho"
        rule macho_test {
            condition:
                macho.dylib_present("/usr/lib/libSystem.B.dylib")
        }
        "#,
        &macho_data
    );
```

## Finished Work

I amended to my PR where I add the dylinker parsing and fix a bug in YARA-X here: [#67](https://github.com/VirusTotal/yara-x/pull/67) :)