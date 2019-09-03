# from unicorn import *
# from unicorn.x86_const import *

# import struct

# ## Add debugging.
# # def hook_code(mu, address, size, user_data):
# #     instruction = mu.mem_read(address, size)
# #     instruction_str = ''.join('{:02x} '.format(x) for x in instruction)
# #     print('# Tracing instruction at 0x%x, instruction size = 0x%x, instruction = %s' % (address, size, instruction_str))

# instructions_skip_list = [0x00000000004004EF, 0x00000000004004F6, 0x0000000000400502, 0x000000000040054F]

# FIBONACCI_ENTRY = 0x0000000000400670
# FIBONACCI_END = [0x00000000004006F1, 0x0000000000400709]

# stack = []                                          # Stack for storing the arguments
# d = {}                                              # Dictionary that holds return values for given function arguments 

# def hook_code(mu, address, size, user_data):  
#     print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))

#     if address in instructions_skip_list:
#         mu.reg_write(UC_X86_REG_RIP, address+size)

#     elif address == 0x400560:                       # That instruction writes a byte of the flag
#         c = mu.reg_read(UC_X86_REG_RDI)
#         print(chr(c))
#         mu.reg_write(UC_X86_REG_RIP, address+size)

#     elif address == FIBONACCI_ENTRY:                # Are we at the beginning of fibonacci function?
#         arg0 = mu.reg_read(UC_X86_REG_RDI)          # Read the first argument. Tt is passed via RDI
#         r_rsi = mu.reg_read(UC_X86_REG_RSI)         # Read the second argument which is a reference
#         arg1 = u32(mu.mem_read(r_rsi, 4))           # Read the second argument from reference

#         if (arg0,arg1) in d:                        # Check whether return values for this function are already saved.
#             (ret_rax, ret_ref) = d[(arg0,arg1)]
#             mu.reg_write(UC_X86_REG_RAX, ret_rax)   # Set return value in RAX register
#             mu.mem_write(r_rsi, p32(ret_ref))       # Set retun value through reference
#             mu.reg_write(UC_X86_REG_RIP, 0x400582)  # Set RIP to point at RET instruction. We want to return from fibonacci function

#         else:
#             stack.append((arg0,arg1,r_rsi))         # If return values are not saved for these arguments, add them to stack.

#     elif address in FIBONACCI_END:
#         (arg0, arg1, r_rsi) = stack.pop()           # We know arguments when exiting the function

#         ret_rax = mu.reg_read(UC_X86_REG_RAX)       # Read the return value that is stored in RAX
#         ret_ref = u32(mu.mem_read(r_rsi,4))         # Read the return value that is passed reference
#         d[(arg0, arg1)]=(ret_rax, ret_ref)          # Remember the return values for this argument pair



# # def hook_code(mu, address, size, user_data):  
# #     # print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size)) 
# #     if address in instructions_skip_list:
# #         mu.reg_write(UC_X86_REG_RIP, address+size)

# #     elif address == 0x400560: #that instruction writes a byte of the flag
# #         c = mu.reg_read(UC_X86_REG_RDI)
# #         print(chr(c))
# #         mu.reg_write(UC_X86_REG_RIP, address+size)

# def read(name):
#     with open(name, 'rb') as f:
#         return f.read()

# def u32(data):
#     return struct.unpack("I", data)[0]

# def p32(num):
#     return struct.pack("I", num)


# mu = Uc (UC_ARCH_X86, UC_MODE_64)

# BASE = 0x400000
# STACK_ADDR = 0x0
# STACK_SIZE = 1024*1024

# mu.mem_map(BASE, 1024*1024)
# mu.mem_map(STACK_ADDR, STACK_SIZE)

# mu.mem_write(BASE, read("./fibonacci"))
# mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE - 1)

# mu.hook_add(UC_HOOK_CODE, hook_code, begin=0x00000000004004E0, end=0x00000000004004E0+140)
# mu.emu_start(0x00000000004004E0, 0x0000000000400575)



# CODE = b"xe8xffxffxffxffxc0x5dx6ax05x5bx29xddx83xc5x4ex89xe9x6ax02x03x0cx24x5bx31xd2x66xbax12x00x8bx39xc1xe7x10xc1xefx10x81xe9xfexffxffxffx8bx45x00xc1xe0x10xc1xe8x10x89xc3x09xfbx21xf8xf7xd0x21xd8x66x89x45x00x83xc5x02x4ax85xd2x0fx85xcfxffxffxffxecx37x75x5dx7ax05x28xedx24xedx24xedx0bx88x7fxebx50x98x38xf9x5cx96x2bx96x70xfexc6xffxc6xffx9fx32x1fx58x1ex00xd3x80" 



# from capstone import *

# # CODE = b"\x55\x48\x8b\x05\xb8\x13\x00\x00"

# md = Cs(CS_ARCH_X86, CS_MODE_32)
# for i in md.disasm(CODE, 0x1000):
#     print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))




from unicorn import *
from unicorn.x86_const import *

shellcode = "xe8xffxffxffxffxc0x5dx6ax05x5bx29xddx83xc5x4ex89xe9x6ax02x03x0cx24x5bx31xd2x66xbax12x00x8bx39xc1xe7x10xc1xefx10x81xe9xfexffxffxffx8bx45x00xc1xe0x10xc1xe8x10x89xc3x09xfbx21xf8xf7xd0x21xd8x66x89x45x00x83xc5x02x4ax85xd2x0fx85xcfxffxffxffxecx37x75x5dx7ax05x28xedx24xedx24xedx0bx88x7fxebx50x98x38xf9x5cx96x2bx96x70xfexc6xffxc6xffx9fx32x1fx58x1ex00xd3x80" 


BASE = 0x400000
STACK_ADDR = 0x0
STACK_SIZE = 1024*1024

mu = Uc (UC_ARCH_X86, UC_MODE_32)

mu.mem_map(BASE, 1024*1024)
mu.mem_map(STACK_ADDR, STACK_SIZE)


mu.mem_write(BASE, shellcode)
# mu.reg_write(UC_X86_REG_ESP, STACK_ADDR + STACK_SIZE/2)

# def syscall_num_to_name(num):
#     syscalls = {1: "sys_exit", 15: "sys_chmod"}
#     return syscalls[num]

# def hook_code(mu, address, size, user_data):
#     #print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))  

#     machine_code = mu.mem_read(address, size)
#     if machine_code == "xcdx80":

#         r_eax = mu.reg_read(UC_X86_REG_EAX)
#         r_ebx = mu.reg_read(UC_X86_REG_EBX)
#         r_ecx = mu.reg_read(UC_X86_REG_ECX)
#         r_edx = mu.reg_read(UC_X86_REG_EDX)
#         syscall_name = syscall_num_to_name(r_eax)

#         print("--------------")
#         print("We intercepted system call: "+syscall_name)

#         if syscall_name == "sys_chmod":
#             s = mu.mem_read(r_ebx, 20).split("x00")[0]
#             print("arg0 = 0x%x -> %s" % (r_ebx, s))
#             print("arg1 = " + oct(r_ecx))
#         elif syscall_name == "sys_exit":
#             print("arg0 = " + hex(r_ebx))
#             exit()

#         mu.reg_write(UC_X86_REG_EIP, address + size)

# mu.hook_add(UC_HOOK_CODE, hook_code)

# mu.emu_start(BASE, BASE-1)