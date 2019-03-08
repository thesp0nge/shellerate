import secrets
import logging

from shellerate.utils import strings

def has_restricted_chars(string, r_chars=[]):
  for i in r_chars:
    if i in string:
      return True
  return false

# def push_eax_
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



def bit_not(n, bits=8):
  return (1<<bits-1) - 1 - n

