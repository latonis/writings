# 100 Days of Yara in 2024: Day 04
Back to parsing some more data from the Mach-O headers and your regularly scheduled programming. On day 02, we covered parsing UUID load commands, as it was some metadata that is generated and then included in the binary, *maybe*. If it is spoofed, we could possibly cluster on it if a malware author doesn't chage it for various parts of the development cycle. 

## Motivation
I'd like to continue that trend of parsing more data from the Mach-O binaries that allows us a similar view into the development environment or values assigned in metadata about the binary. As such, I chose to parse the `version_min_command` data structures. This covers the following load commands:
- `LC_VERSION_MIN_MACOSX`
- `LC_VERSION_MIN_IPHONEOS`
- `LC_VERSION_MIN_WATCHOS`
- `LC_VERSION_MIN_TVOS`

These pieces of metadata can be used to comb through numerous binaries and only find specific ones, filter out older (or newer) compiled binaries, and a lot more. I think there's some potential here for clustering too with combining it with other information that we can glean from development environments of TAs.

For context on the purpose of this data in Mach-O files, it allows the developer to set what versions of the OS the application *should* run on. It could be based on calling system APIs only available or up to a certain version OR it could be arbitrary and just selected during the development cycle. Regardless, it is still an interesting piece of metadata we should have access to when writing YARA rules.

## Structure
The load commands all follow the same structure, the only difference is the actual initial `load_command` value that lets us know which device the data is for: macOS, iPhoneOS, WatchOS, or TVOS.
We'll open up that [`loader.h`](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h) file for the Mach-O header for reference.

```c
/*
 * The version_min_command contains the min OS version on which this 
 * binary was built to run.
 */
struct version_min_command {
    uint32_t	cmd;		/* LC_VERSION_MIN_MACOSX or
				   LC_VERSION_MIN_IPHONEOS  */
    uint32_t	cmdsize;	/* sizeof(struct min_version_command) */
    uint32_t	version;	/* X.Y.Z is encoded in nibbles xxxx.yy.zz */
    uint32_t	sdk;		/* X.Y.Z is encoded in nibbles xxxx.yy.zz */
};
```

## Parsing
We can see from the struct above, there's not too much here to parse. Theres two unsigned 32-bit integers we're concerned with: `version` and `sdk`. This is simple enough to parse with `nom`:
```rust
  let (input, version) = le_u32(input)?;
  let (input, sdk) = le_u32(input)?;
```

The fun part is parsing those integers into the appropriate version strings, which is encoded as `X.Y.Z is encoded in nibbles xxxx.yy.zz`. A nibble meaning 4 bits or half a byte. As such, we can parse the version numbers from the unsigned 32-bit integer and translate it into a string like so:
```rust
fn convert_to_version_string(decimal_number: u32) -> String {
    let major = decimal_number >> 16;
    let minor = (decimal_number >> 8) & 0xFF;
    let patch = decimal_number & 0xFF;
    format!("{}.{}.{}", major, minor, patch)
}
```

## Final Result

Looking at the goldenfiles used for testing, we can see the following is now being parsed:
```
  min_version_mac_os:
      cmd: 36
      cmdsize: 16
      version: "10.9.0"
      sdk: "10.10.0"
```
As with all previous days, I have created a PR ([#56](https://github.com/VirusTotal/yara-x/pull/56)) for YARA-X :)