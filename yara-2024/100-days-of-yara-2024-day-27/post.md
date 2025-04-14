# 100 Days of Yara in 2024: Day 27
In [Day 24](https://jacoblatonis.me/posts/100-days-of-yara-2024-day-24), [Day 25](https://jacoblatonis.me/posts/100-days-of-yara-2024-day-25), [Day 26](https://jacoblatonis.me/posts/100-days-of-yara-2024-day-26) we focused on building YARA-X within a devcontainer, MacOS, and Linux. However, maybe you have a Windows machine and you don't want to learn docker or anything and just want to clone, install prerequisites and build locally on your Windows machine. Let's do that!

## Installing Prerequisites
Buckle up, there's a lot of pre-reqs for Windows to get it to compile successfully!

Windows doesn't come natively with Git, so that should be the first thing we install! You can install from the instructions here: https://git-scm.com/download/win

If you don't have Rust installed yet, that would be a good first step: https://www.rust-lang.org/tools/install.
- You may also need to install Visual Studio C++ Build Tools as well, bundled with Rust

You will also need to install Python 3.x to build the Python hooks: https://www.python.org/downloads/.

You also need to install OpenSSL for Windows: https://slproweb.com/products/Win32OpenSSL.html

After installing OpenSSL, you need to set an environment variable in Git bash:

```bash
export OPENSSL_DIR="C:\Program Files\OpenSSL-Win64"
```

## Cloning the repo
You can clone the repo wherever you'd like, I'm going to clone `yara-x` to my home directory in Windows (`%HOMEPATH%` or `~` in git bash) using git bash, which was installed earlier with git.

To clone the repo to your home directory:
```bash
cd ~
git clone https://github.com/VirusTotal/yara-x.git
```

## Building yara-x
To build `yara-x`, you can do the following:

```bash
cd ~/yara-x
cargo build
```

You will be presented with the following if it is successful:

![good build in cargo](/static/images/100-days-of-yara-2024-day-27/good.png)

## Adding the build directory to your PATH
To be able to call our latest build from anywhere, let's add the debug build path to our PATH environment (if you're using `zsh`).

```bash
echo "export PATH=\"$PATH:$HOME/yara-x/target/debug\"" >> ~/.bashrc
source ~/.bashrc
```

## Running it!

Assuming you've successfully built yara-x and have it linked as shown above, you can now run `yr`:

![yr command](/static/images/100-days-of-yara-2024-day-27/yr.png)

## All in All
Today was a good day for stepping back and allowing others to begin trying out YARA-X and seeing the advantages and how to use them right now. We have now checked off all the operating systems I planned on covering, devcontainers, Linux, MacOS, and Windows. :)