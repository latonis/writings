# 100 Days of Yara in 2024: Day 33
In Day 02 and Day 32, I focused on maintenance for YARA-X itself. In both of these days, we encountered a deprecation notice with a specific repo: [`aig787/cargo-udeps-action`](https://github.com/aig787/cargo-udeps-action). I opened an issue ([#4](https://github.com/aig787/cargo-udeps-action/issues/4)) to document the deprecation notice way back in Day 02, and we're facing it again in Day 32 and Day 33, so I decided to open a PR to remedy it!


This repository is for a GitHub Action that checks for unused dependencies in Rust projects as a code quality check.

## Fixing the Warnings
As the deprecation warnings in Day 02 warned of `node12` deprecation and Day 32 warned of `node16` deprecation, the action needs to be updated to run on *at least* `node20`. To fix this, we can submit a PR for the `action.yml` in the repository which declares what it runs on.

![screenshot of version change for node in repo](/static/images/100-days-of-yara-2024-day-33/change.png)

Additionally, I bumped the version by a patch increment (1.0.0 -> 1.0.1) so the developer can release a new version with the fix.

## Finished Work
Again, not everything is glamarous in development, and this is one of those annoying chores that needed to be done to clear up some tech debt. :)

This specific work implemented today can be seen in [#5](https://github.com/aig787/cargo-udeps-action/pull/5) on [`aig787/cargo-udeps-action`](https://github.com/aig787/cargo-udeps-action), which YARA-X uses.