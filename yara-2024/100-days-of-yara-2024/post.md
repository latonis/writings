# 100 Days of Yara in 2024

how long is 100 days really?

## Main
As the year draws to a close, I am beginning to layout how I plan to approach [#100DaysofYara](https://twitter.com/hashtag/100DaysOfYara). As mentioned in my previous [post](https://jacoblatonis.me/posts/yara-and-me), I am going to focus on the development side of YARA/YARA-X and improving the Mach-O module as much as I can. Currently, I've two PRs ready for review on YARA-X, which focus on some quality of life changes in how numbers can be represented (using _ for clarity in displaying numbers, like [Rust does](https://doc.rust-lang.org/rust-by-example/primitives/literals.html#:~:text=Underscores%20can%20be%20inserted%20in,The%20associated%20type%20is%20f64%20.) [see image below]), and parsing `LC_VERSION_MIN` commands for clustering on those attributes. The PRs are both in review (open source contributions and the process that follows aren't always lightning fast, believe it or not).

![screenshot of rust code that shows ](/static/images/100-days-of-yara-2024/rust_underscore.png)

There's a lot I would like to accomplish for the Mach-O module and YARA-X as a whole, and I am excited to get started. While I wait eagerly and in anticipation for an exciting upcoming 100 days, I must give a big nod towards [Greg Lesnewich](https://twitter.com/greglesnewich) for getting me interested in this to begin with. 100 days seems a bit daunting at first, but I am truly excited to start the process and get to improving YARA-X and YARA in whichever ways I can. I plan to blog every day and document my progress on my contributions, troubles, frustrations, and more. I've even got a Trello board ready to track what I want to work on and when!!

![Trello Board for Jacob's YARA-X development](/static/images/100-days-of-yara-2024/trello.png)

## Side Topic
On a side note, I decided to move away from GitHub pages and using a static website and wrote my own project in Go + htmx, which still uses markdown and converts them into html (read as htmx, barely) which is then presented to you, the reader. If you're interested in seeing the insides of the project, the [source code](https://github.com/latonis/content-server) is hosted on my GitHub. It's pretty simple, but it accomplishes what I need it to do.

## Final Note
As I am wrapping up this post, I want to dive into something that I addmitedly spent more than a few minutes focusing on. During the redesign of the blog and thinking about what I wanted to include in it, I struggled to find a design and template that I liked to present all of my writings to the public internet. After a bit of thinking, I decided the style doesn't matter, **at all**. The purpose of these blogs is so I can help educate others into open source contributions and bettering the ecosystem when folks want to (or need to) contribute. 

After this realization, I decided to not use a pretty template or blog system, I am leaving it as barebones html/htmx and a few (less than 10?) lines of CSS. This allows me to focus on the content (the real exciting stuff!) and contributing to the community, instead of worrying about the style, presentation, and layout of the content. There's been a lot of flash and awe in security lately, and I want to focus on the content and learning itself, not the presentation layer ☺. 

Here's to focusing on the content and improving the tools we use everyday to protect real people and organizations, not worrying about a blog template or color scheme.

![cheers gif](../../static/images/100-days-of-yara-2024/cheers.webp)

