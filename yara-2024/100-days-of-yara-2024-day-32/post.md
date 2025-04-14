# 100 Days of Yara in 2024: Day 32
Waaaaay back in Day 2, I focused on maintenance and chores being an integral part of open source projects. I'm happy to report back I attended to some more chores and will document the process below (hint, it's more deprecation warnings for node versions).

## Noticing the Warnings
After checking some tests for my (and other) work in YARA-X, I noticed somre more GitHub Actions warnings:

![screenshot of actions warnings](/static/images/100-days-of-yara-2024-day-32/warnings-tests.png)

While these aren't necesarrily the end of the world, I like to handle them as I see them so technical debt and maintenance work does not pile up on the back end. Plus, it frees up other developers' time by them not having to do them :).

## Fixing the Warnings
Fortunately for these actions, all of the authors had already released new versions of the action to account for this, so it was just a matter of updating the version number in the actions YAML file to account for that.

## Finished Work
This specific work implemented today can be seen in [#80](https://github.com/VirusTotal/yara-x/pull/80) on YARA-X.

As you can see from the updated test annotations, those warnings have disappeared, except for one which I am not sure where it is originating from, as those actions are no longer called in any workflows.

![new screenshot of actions warnings after updates](/static/images/100-days-of-yara-2024-day-32/warnings-tests-new.png)