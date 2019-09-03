from unicorn import *
from unicorn.arm_const import *
from elftools.elf.elffile import ELFFile

filename = 'libsgavmpso-6.4.31.so'
with open(filename, 'rb') as f:
    elffile = ELFFile(f)
    print(elffile)
    print(dir(elffile))
    print(elffile._file_stringtable_section.header)
    print(dir(elffile._file_stringtable_section))
    print(elffile.num_sections())
    print(elffile.num_segments())
    for i in elffile.iter_sections():
        print(i)
        print(i.name)
        print(i.header)
        print(i.data)
        # print(dir(i))



