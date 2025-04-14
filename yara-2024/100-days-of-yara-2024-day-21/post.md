# 100 Days of Yara in 2024: Day 21
We've parsed superblobs, we've parsed code signature blobs, and we've parsed blob indexes, but there's still some blobs left to parse! I'm currently working on parsing entitlements for Mach-O binaries.

## The Context
If you're unfamiliar with Mach-O entitlements, entitlements are an XML section embedded into a Mach-O binary that allows the operating system to know what permissions are required for running (or that the program is asking for).

Access to these entitlements grant applications specific capabilities or rights to do certain actions or access certain items.

You can read more about them here: https://developer.apple.com/documentation/bundleresources/entitlements

## The Data Layout
Entitlement information has its own particular magic bytes identifier and code signature slot identifier:

```
CSSLOT_ENTITLEMENTS                  SlotType = 5
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171,	/* embedded entitlements */

```
## Parsing the Data
I'm still working on parsing this data. When examining the a Mach-O binary that has embedded entitlements, we can see them clearly:

![hex dump of a Mach-O binary showing the entitlements XML](/static/images/100-days-of-yara-2024-day-21/hexdump.png)

## End Result
Thankfully, some of the binaries in the Mach-O testdata directory in YARA-X contain entitlement data, so we're good to test with those! I'm not fully parsing the data yet, but I can see the XML in the data and am calculating the offsets properly.

## Finished Work
No PR yet, but it will be coming soon :)