from unicorn import *
from unicorn.arm_const import *
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from androidemu.internal import get_segment_protection, arm

import struct


# filename = 'libsgavmpso-6.4.31.so'
# with open(filename, 'rb') as f:
#     elffile = ELFFile(f)
#     print(elffile)
#     print(dir(elffile))
#     print(elffile._file_stringtable_section.header)
#     print(dir(elffile._file_stringtable_section))
#     print(elffile.num_sections())
#     print(elffile.num_segments())
#     for i in elffile.iter_sections():
#         print(i)
#         print(i.name)
#         print(i.header)
#         print(i.data)
#         # print(dir(i))

#     dynsym = elffile.get_section_by_name(".dynsym")
#     print(dynsym)



# filename = 'example_binaries/libnative-lib_jni.so'
filename = 'libsgavmpso-6.4.31.so'
with open(filename, 'rb') as fstream:
    elffile = ELFFile(fstream)
    # print(elffile)
    # print(dir(elffile))
    # print(elffile._file_stringtable_section.header)
    # print(dir(elffile._file_stringtable_section))
    # print(elffile.num_sections())
    # print(elffile.num_segments())
    # for i in elffile.iter_sections():
    #     print(i)
    #     print(i.name)
    #     print(i.header)
    #     print(i.data)
    #     # print(dir(i))

    # dynsym = elffile.get_section_by_name(".dynsym")
    # print(dynsym)

    # for rel in rel_section.iter_relocations():
    #         rel_info_type = rel['r_info_type']
    #         rel_addr = rel['r_offset']
    # sym = dynsym.get_symbol(rel['r_info_sym'])
    # print(sym)
    dynamic = elffile.header.e_type
    print(dynamic)

    load_segments = [x for x in elffile.iter_segments() if x.header.p_type == 'PT_LOAD']
    print(load_segments)
    # Find bounds of the load segments.
    bound_low = 0
    bound_high = 0

    for segment in load_segments:
        if segment.header.p_memsz == 0:
            continue
        if bound_low > segment.header.p_vaddr:
            bound_low = segment.header.p_vaddr

        high = segment.header.p_vaddr + segment.header.p_memsz

        if bound_high < high:
            bound_high = high

    print(bound_high)
    print(bound_low)

    # for x in elffile.iter_segments():
    #     # print(x.header.p_type)
    #     if x.header.p_type == "PT_DYNAMIC":
    #         print(x.header.p_type)
    #         for tag in x.iter_tags():
    #             print(tag.entry.d_tag)
    #             if tag.entry.d_tag == "DT_INIT_ARRAYSZ":
    #                 init_array_size = tag.entry.d_val
    #                 print(init_array_size)
    #             elif tag.entry.d_tag == "DT_INIT_ARRAY":
    #                 init_array_offset = tag.entry.d_val
    #                 print(init_array_offset)


    for segment in load_segments:
        prot = get_segment_protection(segment.header.p_flags)
        print(prot)
        print(segment.header.p_vaddr)
        print(segment.header.p_memsz)

    rel_section = None
    for section in elffile.iter_sections():
        if not isinstance(section, RelocationSection):
            continue
        rel_section = section
        break

    print(rel_section)

    # Find init array.
    init_array_size = 0
    init_array_offset = 0
    init_array = []
    for x in elffile.iter_segments():
        if x.header.p_type == "PT_DYNAMIC":
            for tag in x.iter_tags():
                if tag.entry.d_tag == "DT_INIT_ARRAYSZ":
                    init_array_size = tag.entry.d_val
                elif tag.entry.d_tag == "DT_INIT_ARRAY":
                    init_array_offset = tag.entry.d_val

    print(init_array_size)
    print(init_array_offset)

    for _ in range(int(init_array_size / 4)):
        # covert va to file offset
        for seg in load_segments:
            if seg.header.p_vaddr <= init_array_offset < seg.header.p_vaddr + seg.header.p_memsz:
                init_array_foffset = init_array_offset - seg.header.p_vaddr + seg.header.p_offset
        print(init_array_foffset)
        fstream.seek(init_array_foffset)
        data = fstream.read(4)
        print(data)
        fun_ptr = struct.unpack('I', data)[0]
        print(fun_ptr)

        if fun_ptr != 0:
            # fun_ptr += load_base
            # init_array.append(fun_ptr + load_base)
            print ("find init array for :%s %x" % (filename, fun_ptr))
        else:
            # search in reloc
            for rel in rel_section.iter_relocations():
                print(rel)
                # rel_info_type = rel['r_info_type']
                # rel_addr = rel['r_offset']
                # if rel_info_type == arm.R_ARM_ABS32 and rel_addr == init_array_offset:
                #     sym = dynsym.get_symbol(rel['r_info_sym'])
                #     sym_value = sym['st_value']
                #     init_array.append(load_base + sym_value)
                #     # print ("find init array for :%s %x" % (filename, sym_value))
                #     break


