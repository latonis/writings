# 100 Days of Yara in 2024: Day 07
I'm currently working on another PR for parsing some more load commands for Mach-O binaries. However, I was trying to find something in the documentation, and I realized it does not exist currently.

## The Context
YARA-X has their test binaries stored in a very particular way. For the first step, the binary is converted to [Intel Hex](https://developer.arm.com/documentation/ka003292/latest/) format. After that, the file is then zipped into a zip archive and placed in the appropriate folder.

## Formatting the files appropriately

To convert the binary to Intel Hex format, we can use the scripts provided at [python-intelhex/intelhex](https://github.com/python-intelhex/intelhex/).

To start, we need the raw binary with the sha256 of the binary as its identifier.

```bash
bin2hex.py <sha256_hash> <sha256_hash>.in
zip <sha256_hash>.in.zip <sha256_hash>.in
mv <sha256_hash>.in.zip <location_of_yara-x>/yara-x/src/modules/<module>/tests/testdata/
```

## Converting the Files back to Original Format
If you need the files back in binary form, you can inverse the steps above.

```bash
unzip <sha256_hash>.in.zip
hex2bin.py <sha256_hash>.in <sha256_hash>
```

You can now explore the binary in its native form.

## Finished Work

I also submitted a PR to YARA-X documentation here: [#69](https://github.com/VirusTotal/yara-x/pull/69)