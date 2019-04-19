def pad(string):
  ret = string + "\\x90" * (4-(string.count("\\x")%4))
  return ret

def split(string, n=2):
  return [string[i:i+n] for i in range(0, len(string), n)]

# This method takes a byte in a printable char representation and give the
# hex code.
#   "\\x31" => "31"
def from_char_to_hexcode(a):
  return a.replace("\\x", "")

def from_string_to_payload(str):
  a=split(str)
  return ''.join('\\x'+x.zfill(2) for x in a)
  

def swap(x):
  s=x[6:8] + x[4:6] + x[2:4] + x[0:2]
  return s

