import struct
import textwrap
from shellerate.encoder.encoder import Encoder
from binascii import unhexlify, hexlify;

#from shellerate.encoder.not_encoder import NotEncoder
#e=NotEncoder("\\x31")
#e.encode()
#e.payload()

class NotEncoder(Encoder):
  def __init__(self, shellcode):
    super(NotEncoder, self).__init__(shellcode)

  def encode(self, output_format="c"):
    padded_shellcode = self.pad(self.shellcode())
    output = ""
    for c in textwrap.wrap(padded_shellcode, 16):
      val=self.from_char_to_hexcode(c)
      neg=self.not_byte(val) + 1
      print(c)
      print(val)
      print(neg)


      if output_format == "c":
        output += ''.join('\\x{:02x}'.format(x) for x in struct.pack("l", neg )).replace("\\xff\\xff\\xff\\xff", "")
      if output_format == "asm":
        output += ''.join('0x{:02x}, '.format(x) for x in struct.pack("l", neg)).replace("\\xff\\xff\\xff\\xff", "")
      if output_format == "raw":
        output += ''.join('{:02x}'.format(x) for x in struct.pack("l",  neg)).replace("\\xff\\xff\\xff\\xff", "")

    if output_format == "asm":
      return output[::-2]

    return output

  def payload(self):
    stub="\\xeb\\x26\\x5e\\x8d\\x3e\\x31\\xc0\\x31\\xdb\\x31\\xd2\\x89\\xe2\\x8b\\x1c\\x06\\x84\\xdb\\x74\\x0f\\xf7\\xd3\\x83\\xc3\\x01\\x0f\\xcb\\x53\\x83\\xc7\\x04\\x04\\x04\\xeb\\xea\\x83\\xea\\x04\\xff\\xe2\\xe8\\xd5\\xff\\xff\\xff"
    return stub + self.encode()


