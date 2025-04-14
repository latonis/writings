# 100 Days of Yara in 2024: Day 10
I promised another function to search more data, and this time we're back for rpaths!

## The Plan Ahead
We don't have to parse any new data this time either, we just have to implement the function that allows us to search the data we do have parsed already, just like yesterday :).

## Implementing the Function
We're gonna leverage the wonderful macros for defining functions within modules again. As a reminder, the macro is `#[module_export(name = "<function_name>")]`

```rust
#[module_export(name = "rpath_present")]
fn rpaths_present(ctx: &ScanContext, rpath: RuntimeString) -> Option<bool> {
    let macho = ctx.module_output::<Macho>()?;
    let expected_rpath = rpath.as_bstr(ctx);

    for rp in macho.rpaths.iter() {
        if rp.path.as_ref().is_some_and(|path| {
            expected_rpath.eq_ignore_ascii_case(path.as_bytes())
        }) {
            return Some(true);
        }
    }

    for file in macho.file.iter() {
        for rp in file.rpaths.iter() {
            if rp.path.as_ref().is_some_and(|path| {
                expected_rpath.eq_ignore_ascii_case(path.as_bytes())
            }) {
                return Some(true);
            }
        }
    }

    Some(false)
}
```

Again, probably a rust friendly, idiomatic way to write this, we'll get there eventually :P.

## End Result
With this second newly implemented function, you can now search rpaths in a YARA rule like so:

```
import "macho"

rule macho_test {
  condition:
    macho.rpath_present("@loader_path/../Frameworks")
}
```

![image showing a command line terminal with a passing yara rule](/static/images/100-days-of-yara-2024-day-10/image.png)

## Tests
I wrote a few tests to validate that the function works as expected:
```rust
    rule_false!(
        r#"
        import "macho"
        rule test {
            condition:
                macho.rpath_present("totally not present rpath")
        }
        "#
    );

    rule_false!(
        r#"
        import "macho"
        rule macho_test {
            condition:
                macho.rpath_present("@loader_path/../Frameworks")
        }
        "#,
        &tiny_universal_macho_data
    );

    rule_true!(
        r#"
        import "macho"
        rule macho_test {
            condition:
                macho.rpath_present("@loader_path/../Frameworks")
        }
        "#,
        &x86_macho_data
    );
```

## Finished Work

I amended to my PR where I add the dylinker parsing, fix a bug, and add the previous dylib function as well in YARA-X here: [#67](https://github.com/VirusTotal/yara-x/pull/67) :)