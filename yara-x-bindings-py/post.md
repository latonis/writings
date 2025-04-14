# Summary
In this small write-up, I'm going to document how one can use YARA-X bindings in Python. For right now, the Python package is not being published to PyPi or any other repositories, as it is still under active development and not ready for release. However, we can build it and install it locally to get some use with it before YARA-X goes into release.

# Getting Started
To get started, you need YARA-X cloned locally. This can be done with `git clone git@github.com:VirusTotal/yara-x.git`.

Once cloned, navigate into the directory with `cd yara-x`. Once in the repository, we can set up a virtual environment with `python -m venv .venv` and activate it with `source ./venv/bin/activate`.

You'll know it is activated when you see the `(.venv)` in your shell:

![venv output](/static/images/yara-x-bindings-py/venv.png)

Once activated, let's install the dependencies we need:
`pip install maturin`.

To build, we can run `maturin develop --manifest-path py/Cargo.toml`. You'll be presented with something like this:

![maturin output](/static/images/yara-x-bindings-py/maturin.png)

Once finished, to test if we successfully see `yara_x` installed and its features, we can run `python` to start an interactive session.

```bash
(.venv) ┌─[jacob@jacobs-MacBook-Pro] - [~/src/yara-x] - [1395]
└─[$] python                                                                                               [18:53:37]
Python 3.9.6 (default, Nov 10 2023, 13:38:27)
[Clang 15.0.0 (clang-1500.1.0.2.5)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> import yara_x
>>> dir(yara_x)
['Compiler', 'Match', 'Pattern', 'Rule', 'Rules', 'Scanner', '__all__', '__builtins__', '__cached__', '__doc__', '__file__', '__loader__', '__name__', '__package__', '__path__', '__spec__', 'compile', 'yara_x']
>>>
```


Now, let's test out getting module outputs from scanning a file:

```python
import yara_x
import os

rule=yara_x.compile('import "macho" rule macho_test {condition: true}')

for root, _, files in os.walk(".", topdown=False):
    for name in files:
      print(f"Scanning: {name}")
      with open(os.path.join(root, name), "rb") as f:
        result = rule.scan(f.read())
		print(module_output := result.module_outputs)
```

The above python file brings the following output:

```bash
(.venv) ┌─[jacob@jacobs-MacBook-Pro] - [~/yara/malware] - [1414]
└─[$] python test_yara_x.py                                                                                                     

Scanning: test1
{'macho': {}}
Scanning: tiny_universal
{'macho': {'fatMagic': 3405691582, 'nfatArch': 2, 'fatArch': [{'cputype': 7, 'cpusubtype': 3, 'offset': '4096', 'size': '8512', 'align': 12, 'reserved': 0}, {'cputype': 16777223, 'cpusubtype': 2147483651, 'offset': '16384', 'size': '8544', 'align': 12, 'reserved': 0}], 'file': [{'magic': 3472551422, 'cputype': 7, 'cpusubtype': 3, 'filetype': 2, 'ncmds': 16, 'sizeofcmds': 1060, 'flags': 18874501, 'numberOfSegments': '4', 'dynamicLinker': 'L3Vzci9saWIvZHlsZA==', 'entryPoint': '3808', 'stackSize': '0', 'sourceVersion': '0.0.0.0.0', 'segments': [{'segname': 'X19QQUdFWkVSTw==', 'vmaddr': '0', 'vmsize': '4096', 'fileoff': '0', 'filesize': '0', 'maxprot': 0, 'initprot': 0, 'nsects': 0, 'flags': 0}, {'segname': 'X19URVhU', 'vmaddr': '4096', 'vmsize': '4096', 'fileoff': '0', 'filesize': '4096', 'maxprot': 7, 'initprot': 5, 'nsects': 5, 'flags': 0, 'sections': [{'segname': 'X19URVhU', 'sectname': 'X190ZXh0', 'addr': '7824', 'size': '214', 'offset': 3728, 'align': 4, 'reloff': 0, 'nreloc': 0, 'flags': 2147484672, 'reserved1': 0, 'reserved2': 0}, {'segname': 'X19URVhU'
[...]
}
```

If I wanted to look for only FAT Mach-O files, I could change the above script to look for them like so:

```python
import yara_x
import os

rule=yara_x.compile('import "macho" rule macho_test {condition: true}')
macho_fat_arch_files = []

for root, _, files in os.walk(".", topdown=False):
    for name in files:
      print(f"Scanning: {name}")
      with open(os.path.join(root, name), "rb") as f:
        result = rule.scan(f.read())
        print(module_output := result.module_outputs)
        if module_output.get("macho", {}).get("fatArch", None) is not None:
            macho_fat_arch_files.append(name)
    
print(f"FAT Mach-O files found: {macho_fat_arch_files}")
```

and get the following output:

```bash
(.venv) ┌─[jacob@jacobs-MacBook-Pro] - [~/yara/malware] - [1414]
└─[$] python test_yara_x.py                                                                                                                                                           [19:47:49]
Scanning: test1
{'macho': {}}
Scanning: tiny_universal
{'macho': {'fatMagic': 3405691582, 'nfatArch': 2, 'fatArch': [{'cputype': 7, 'cpusubtype': 3, 'offset': '4096', 'size': '8512', 'align': 12, 'reserved': 0}, {'cputype': 16777223, 'cpusubtype': 2147483651, 'offset': '16384', 'size': '8544', 'align': 12, 'reserved': 0}], 'file': [{'magic': 3472551422, 'cputype': 7, 'cpusubtype': 3, 'filetype': 2, 'ncmds': 16, 'sizeofcmds': 1060, 'flags': 18874501, 'numberOfSegments': '4', 'dynamicLinker': 'L3Vzci9saWIvZHlsZA==', 'entryPoint': '3808', 'stackSize': '0', 'sourceVersion': '0.0.0.0.0', 'segments': [{'segname': 'X19QQUdFWkVSTw==', 'vmaddr': '0', 'vmsize': '4096', 'fileoff': '0', 'filesize': '0', 'maxprot': 0, 'initprot': 0, 'nsects': 0, 'flags': 0}, {'segname': 'X19URVhU', 'vmaddr': '4096', 'vmsize': '4096', 'fileoff': '0', 'filesize': '4096', 'maxprot': 7, 'initprot': 5, 'nsects': 5, 'flags': 0, 'sections': [{'segname': 'X19URVhU', 'sectname': 'X190ZXh0', 'addr': '7824', 'size': '214', 'offset': 3728, 'align': 4, 'reloff': 0, 'nreloc': 0, 'flags': 2147484672, 'reserved1': 0, 'reserved2': 0}, {'segname': 'X19URVhU'
[...]
}

FAT Mach-O files found: ['tiny_universal']
```