# 100 Days of Yara in 2024: Day 20
Today is a post about planning for what I want to work on in the upcoming days for YARA-X. We have 80 days remaining in this challenge, and I want to make as much impact as possible to YARA-X and the Mach-O module as I can in this time. I think to effectively do so, a planning session is in order.

## Deriving Next Steps
As we make progress with the `LC_CODE_SIGNATURE` load command, there is still a lot of value we can derive from this particular set of data. With superblobs, blob_indexes, and the certificate blob loaded, our next steps should be to parse out the entitlements and code directory blobs. As such, I've tracked them in my YARA-X Trello board: 

![screenshot of a single trello ticket for code signing segment parsing for Mach-O](/static/images/100-days-of-yara-2024-day-20/code_signing.png)

## After the Code Signing Data

I think after the code signing data, we should parse the offsets of encrypted data in the binary, note load commands, and then move on to writing more functions to better enable the end user to access the data in accessible ways. I think functions for a `contains` method for dylib and rpaths makes sense, as well as checking if entitlements are set and exist in the binary.

![screenshot of to-do items in a trello board](/static/images/100-days-of-yara-2024-day-20/progress.png)

## All in All
At the end of the day, I think no matter which changes we make for the Mach-O module, we're still improving and making general, forward progress, which is fantastic! I want to better enable the MacOS/iOS security community, and I think this is the right way forward.

I don't want to get too bogged down in the details, but I do want to have checklists and some plan going forward to continue the iterative progress and continue improving the Mach-O module.

I think the items I have in the backlog and in-progress sections shown above will allow me to keep chugging along and keep making teh YARA-X world a better place :).

Thanks for reading these so far if you have been reading them, and thanks for following along. The Mach-O progress is making me SO excited for the future of it and YARA-X.