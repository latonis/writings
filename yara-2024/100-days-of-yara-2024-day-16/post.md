# 100 Days of Yara in 2024: Day 16
Today is going to be a short one, but that is okay! *Way* back in [Day 02](https://jacoblatonis.me/posts/100-days-of-yara-2024-day-02), I talked about how chores and maintenance in open source projects remains very important. In [Day 07](https://jacoblatonis.me/posts/100-days-of-yara-2024-day-07), I made a PR on documentation to better allow new contributors to YARA-X to know how to generate test data and files. Victor (the primary maintainer of YARA-X), has some feedback on the update, which I agreed with. For this post, I just wanted to document that collaboration happens often in open source projects, some of it may be very large, and some of it may be small changes like documentation :).

## Description
In my original PR, I suggested adding documentation on how to convert binaries to `ihex` format and from `ihex` format back to binary. However, I suggested the change below:

```
To convert the binary to Intel Hex format, we can use the scripts provided at [python-intelhex/intelhex](https://github.com/python-intelhex/intelhex/).
```

However, Victor suggested adding documentation steps for `objcopy` and `llvm-objcopy`, as they're wider known and generally come with the operating system if on Linux or MacOS, and I agree. Taking Victor's feedback, I broke the documentation into 3 sections:
- Linux (`objcopy`)
- MacOS (`llvm-objcopy`)
- Other operating systems (the `python-intelhex` repo)

This allows for both the well known utilities as well as the Python tool if they cannot convert the binaries using the aforementioned tools. :)

## Finished Work
This post was just to mainly show collaboration occurs at all steps, and it is not all massive code reviews and PRs. Sometimes, it's just a suggestion to change a line or two of markdown to make it easier for new contributors. 

I added this work to the PR to YARA-X here: [#69](https://github.com/VirusTotal/yara-x/pull/69) :)
