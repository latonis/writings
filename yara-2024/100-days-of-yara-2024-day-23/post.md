# 100 Days of Yara in 2024: Day 23
Following our functions with dylibs and rpaths, I figured building on top of our entitlement parsing and having a function to search them would be pretty cool. >:)

## The Plan Ahead
We don't have to parse any new data this time around, we just have to implement the function that allows us to search the data we do have parsed already.

## Implementing the Function
Thankfully, YARA-X already has a well developed framework for implementing functions for modules. With the macro `#[module_export(name = "<function_name>")]``
```rust
/// The function for checking if a given entitlement is present in the main Mach-O or embedded Mach-O files
///
/// # Arguments
///
/// * `ctx`: A mutable reference to the scanning context.
/// * `entitlement`: The name of the entitlement to check if present
///
/// # Returns
///
/// An `Option<bool>` containing if the entitlement is found
#[module_export(name = "entitlement_present")]
fn entitlements_present(
    ctx: &ScanContext,
    entitlement: RuntimeString,
) -> Option<bool> {
    let macho = ctx.module_output::<Macho>()?;
    let expected = entitlement.as_bstr(ctx);

    for entitlement in macho.entitlements.iter() {
        if expected.eq_ignore_ascii_case(entitlement.as_bytes()) {
            return Some(true);
        }
    }

    for file in macho.file.iter() {
        for entitlement in file.entitlements.iter() {
            if expected.eq_ignore_ascii_case(entitlement.as_bytes()) {
                return Some(true);
            }
        }
    }

    Some(false)
}
```

There's probably a more idiomatic way to write this in Rust, and I am sure I will clean it up later. However, for now this works. :)

## End Result
With this newly implemented function, you can now search for entitlements in a YARA rule like so:

```
    import "macho"

    rule macho_entitlement {
        condition:
            macho.entitlement_present("com.apple.security.network.client")
    }
```

## Tests
I wrote a few tests to validate that the function works as expected with out trusty chess binary:
```rust
    rule_true!(
        r#"
        import "macho"
        rule macho_test {
            condition:
                macho.entitlement_present("com.apple.security.network.client")
        }
        "#,
        &chess_macho_data
    );

    rule_false!(
        r#"
        import "macho"
        rule macho_test {
            condition:
                macho.entitlement_present("made-up-entitlement")
        }
        "#,
        &chess_macho_data
    );
```

## Finished Work

I ammended my PR to YARA-X  here: [#73](https://github.com/VirusTotal/yara-x/pull/73) :)