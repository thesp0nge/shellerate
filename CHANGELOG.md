# Changelog

This the Changelog file for the shellerate project. 'shellerate' is pun between
'shell' and 'scellerato', the Italian word for 'wicked'.

'shellerate' is a shellcode generation framework born from the assignments I
took for the SecurityTube Linux Assembly Expert certification process.

You can feature custom encoders, custom crypters, polymorphism and all stuff I
learned in the SLAE certification process.

## [Unreleased]

## [0.5.0] - 2019-xx-xx

### Added
- nop_sled(): creates a NOP sled
- XORity custom encoder
- math, asm_x86 and strings modules
- zero_with_and(): generates a shellcode zeroing a register using 2 ADD
  instructions.
- get_esp_address_in_eax(): saves ESP value into EAX using push and pop
  strategy

### Changed
A lot of work it has been down on encoder classes. Biggest change is the
introduction of encoding strategies support. For such a reason, we must
implement specialized classes doing encoding.

The encoder.py file is moved on a adhoc directory and it will be the main
encoding class with all basic functionalities.

I made the package flat in shellerate directory to make imports easier, will
refactor back later on.

## [0.4.0] - 2019-02-05
### Added
- Adding Win32 bind shell shellcode (taken as is from msfvenom)
### Changed
- Minor tweaks to binary script

## [0.3.0] - 2019-01-08
### Added
- Adding encoder class
- Adding encoder support for bind_shell shellcode

## [0.2.0] - 2018-09-05
### Added
- logging facilities in tcp bind shellcode
- added egg hunter generator for tcp bind shellcode

### Changed
- now shellcode() is a method returning the internal shellcode representation.
  From a semantic versioning point of view, this could reserve a major version
  upgrade, however we didn't reach version 1.0.0 so I can bump only minor
  version.

## [0.1.0] - 2018-09-04
### Added
- x86/Linux: TCP Bind shell shellcode added
