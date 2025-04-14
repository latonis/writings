# 100 Days of Yara in 2024: Day 40
Way back in [Day 23](https://jacoblatonis.me/posts/100-days-of-yara-2024-day-23), I wrote a function to query for entitlements present in a Mach-O binary and it was a part of a PR ([#73](https://github.com/VirusTotal/yara-x/pull/73/)). However, as you've noticed with numerous previous posts, there's a bit of refactoring that needs to happen! Fortunately for us, this function being ported over is the last of the refactoring that needs to happen.

## Implementing the Function
This part hasn't changed for implementation, it still exists in `mod.rs` for the Mach-O module.

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
These are two tests I wrote in the original PR, however I added one more to check to ensure case insensitivity works as applicable.

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

This is the additional test I added.

```rust
    rule_true!(
        r#"
        import "macho"
        rule macho_test {
            condition:
                macho.entitlement_present("COM.ApplE.security.NetWoRK.client")
        }
        "#,
        &chess_macho_data
    );
```



## Finished Work

This finalizes all of the refactoring done in [#78](https://github.com/VirusTotal/yara-x/pull/78/). As such, I've closed out [#73](https://github.com/VirusTotal/yara-x/pull/73/) in favor of [#78](https://github.com/VirusTotal/yara-x/pull/78/).

We can now move on to more features for the Mach-O module instead of the refactoring!! >:)