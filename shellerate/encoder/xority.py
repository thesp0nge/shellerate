import struct
import textwrap
from shellerate.encoder.encoder import Encoder
from binascii import unhexlify, hexlify;

class Xority(Encoder):
  def __init__(self, shellcode):
    super(Xority, self).__init__(shellcode)
  
  # val is the hex representation of the register without 0x
  def calc_xor_key(self, val):

  def encode(self, output_format="c"):
    padded_shellcode = self.pad(self.shellcode())
    output = ""
    for c in textwrap.wrap(padded_shellcode, 16):
      val=self.from_char_to_hexcode(c)
      b_a=self.split(val)

      print(c)
      print(val)
      print(b_a)


      #if output_format == "c":
      #  output += ''.join('\\x{:02x}'.format(x) for x in struct.pack("l", neg )).replace("\\xff\\xff\\xff\\xff", "")
      #if output_format == "asm":
      #  output += ''.join('0x{:02x}, '.format(x) for x in struct.pack("l", neg)).replace("\\xff\\xff\\xff\\xff", "")
      #if output_format == "raw":
      #  output += ''.join('{:02x}'.format(x) for x in struct.pack("l",  neg)).replace("\\xff\\xff\\xff\\xff", "")

    if output_format == "asm":
      return output[::-2]

    return output

  def payload(self):
    stub = ""
    return stub +self.encode()


