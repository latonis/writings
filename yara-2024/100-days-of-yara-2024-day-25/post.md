# 100 Days of Yara in 2024: Day 25
In [Day 24](https://jacoblatonis.me/posts/100-days-of-yara-2024-day-24), we focused on building YARA-X within a dev container. However, maybe you have a Mac and you don't want to learn docker or anything and just want to clone, install prerequisites and build locally on your Mac. Let's do that!

## Cloning the repo
You can clone the repo wherever you'd like, I have a `src` directory I like to keep all my projects in. However, for this tutorial I'm going to assume you clone `yara-x` in `~`, meaning it will be located at `~/yara-x` on your Mac.

To clone the repo to your home directory:

```bash
cd ~
git clone git@github.com:VirusTotal/yara-x.git
```
## Installing Prerequisites
If you don't have Rust installed yet, that would be a good first step: https://www.rust-lang.org/tools/install.

We need OpenSSL to build all of YARA-X and its modules. We can use `brew` for that. To install homebrew, you can find the directions here: https://brew.sh/ 

```bash
brew install openssl
```

## Building yara-x
To build `yara-x`, you can do the following:

```bash
cd ~/yara-x
cargo build
```

You will be presented with the following if it is successful:

![good build in cargo](/static/images/100-days-of-yara-2024-day-25/good.png)

## Adding the build directory to your PATH
To be able to call our latest build from anywhere, let's add the debug build path to our PATH environment (if you're using `zsh`).

```bash
echo "export PATH=$PATH:$HOME/yara-x/target/debug" >> ~/.zshrc
source ~/.zshrc
```

## Running it!

Assuming you've successfully built yara-x and have it linked as shown above, you can now run `yr`:

![yr command](/static/images/100-days-of-yara-2024-day-25/yr.png)

## All in All
Today was a good day for stepping back and allowing others to begin trying out YARA-X and seeing the advantages and how to use them right now. We have now checked off MacOS and devcontainers! Windows next? ;)