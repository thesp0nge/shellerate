import textwrap;
from binascii import unhexlify, hexlify;

class Encoder:
  def __init__(self, shellcode, key):
    self.__shellcode = shellcode;
    self.__key = key;
  
  def pad(self, string):
    ret = string + "\x90" * (4-(len(string)%4))
    return ret

  def xor_str(self, a,b):
    result = int(a, 16) ^ int(b, 16) # convert to integers and xor them
    return '{:x}'.format(result) 

  def swap(self, x):
    s=x[6:8] + x[4:6] + x[2:4] + x[0:2]
    return s

  def encode(self):
    padded_shellcode = self.pad(self.__shellcode)
    padded_hex=hexlify(padded_shellcode.encode())
    shellcode_len=int(len(padded_shellcode))
    ss= '{:x}'.format(shellcode_len)

    shell_len_string = self.swap(self.xor_str(ss*4, self.__key))

    padded_xor_hex=""
    for i in textwrap.wrap(padded_hex.decode(), 8):
        padded_xor_hex+=self.xor_str(i, self.__key)

    padded_xor_swapped=""
    for i in textwrap.wrap(padded_xor_hex, 8):
        padded_xor_swapped+=self.swap(i)


    final_encoded_payload=shell_len_string +padded_xor_swapped

    f=""
    for x in range(0, len(final_encoded_payload), 2):
        f+= "\\x"+final_encoded_payload[x:x+2]

    return f
