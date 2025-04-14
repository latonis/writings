# 100 Days of Yara in 2024: Day 28
Now that I have covered all of the build tutorials for each operating system, it is time to get back to parsing and coding for YARA-X. However, before I dive in, we need to understand a rather significant change that was introduced to the Mach-O module via a PR by Victor (creator of YARA/YARA-X). This PR can be found at [#76](https://github.com/VirusTotal/yara-x/pull/76). You'll notice theres quite a few lines changed and many files changed. I'm gonna dive into that today.

## Diving In
Originally, the Mach-O module for YARA-X was ported from the Mach-O module for YARA and the design structure was left largely the same, leading to some repeated code and structures as well as some very C like decisions. Victor has done some great work on parsing more efficiently with Nom (a Rust parsing library) and defining an implementation for the parser for the Mach-O module.

## A new feature
One of the new features that is really nice is parsing based on the endianness of the file, instead of swapping repeatedly after parsing, which is incredibly great from an efficiency perspective.

## The road ahead
All of these changes and restructuring unfortunately means I'll have to refactor all of my sitting PRs; however, I am happy to do this as this is the better road towards a sustainable module for parsing, testing, and implementing new features. :) 

The path to new and better features is not always straight ahead, sometimes it is as rewrite and refactor or two, a few steps forward, and then more refactoring away :P.

I'm gonna go write some Rust now :)