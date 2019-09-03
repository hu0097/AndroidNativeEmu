import binascii
from unicorn import *
from unicorn.x86_const import *

# shellcode = "xe8xffxffxffxffxc0x5dx6ax05x5bx29xddx83xc5x4ex89xe9x6ax02x03x0cx24x5bx31xd2x66xbax12x00x8bx39xc1xe7x10xc1xefx10x81xe9xfexffxffxffx8bx45x00xc1xe0x10xc1xe8x10x89xc3x09xfbx21xf8xf7xd0x21xd8x66x89x45x00x83xc5x02x4ax85xd2x0fx85xcfxffxffxffxecx37x75x5dx7ax05x28xedx24xedx24xedx0bx88x7fxebx50x98x38xf9x5cx96x2bx96x70xfexc6xffxc6xffx9fx32x1fx58x1ex00xd3x80" 

a = 'e8ffffffffc05d6a055b29dd83c54e89e96a02030c245b31d266ba12008b39c1e710c1ef1081e9feffffff8b4500c1e010c1e81089c309fb21f8f7d021d86689450083c5024a85d20f85cfffffffec37755d7a0528ed24ed24ed0b887feb509838f95c962b9670fec6ffc6ff9f321f581e00d380'
print(binascii.a2b_hex(a))

BASE = 0x400000
STACK_ADDR = 0x0
STACK_SIZE = 1024*1024

mu = Uc (UC_ARCH_X86, UC_MODE_32)

mu.mem_map(BASE, 1024*1024)
mu.mem_map(STACK_ADDR, STACK_SIZE)


mu.mem_write(BASE, binascii.a2b_hex(a))
mu.reg_write(UC_X86_REG_ESP, STACK_ADDR + int(STACK_SIZE/2))

def syscall_num_to_name(num):
    syscalls = {1: "sys_exit", 15: "sys_chmod"}
    return syscalls[num]

def hook_code(mu, address, size, user_data):
    #print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))  

    machine_code = mu.mem_read(address, size)
    print(machine_code)
    if machine_code == binascii.a2b_hex("cd80"):
        print('hooked!!')
        r_eax = mu.reg_read(UC_X86_REG_EAX)
        r_ebx = mu.reg_read(UC_X86_REG_EBX)
        r_ecx = mu.reg_read(UC_X86_REG_ECX)
        r_edx = mu.reg_read(UC_X86_REG_EDX)
        syscall_name = syscall_num_to_name(r_eax)
        print(syscall_name)
        print ("--------------")
        print ("We intercepted system call: {}".format(syscall_name))

        if syscall_name == "sys_chmod":
            print(mu.mem_read(r_ebx, 20))
            s = mu.mem_read(r_ebx, 20).split(binascii.a2b_hex('00'))[0]
            print ("arg0 = 0x%x -> %s" % (r_ebx, s))
            print ("arg1 = " + oct(r_ecx))
        elif syscall_name == "sys_exit":
            print ("arg0 = " + hex(r_ebx))
            exit()

        mu.reg_write(UC_X86_REG_EIP, address + size)

# def hook_code(mu, address, size, user_data):
#     instruction = mu.mem_read(address, size)
#     instruction_str = ''.join('{:02x} '.format(x) for x in instruction)
#     print('# Tracing instruction at 0x%x, instruction size = 0x%x, instruction = %s' % (address, size, instruction_str))


mu.hook_add(UC_HOOK_CODE, hook_code)

mu.emu_start(0x400000, 0x400000 + len(binascii.a2b_hex(a)))

# a = 'e8ffffffffc05d6a055b29dd83c54e89e96a02030c245b31d266ba12008b39c1e710c1ef1081e9feffffff8b4500c1e010c1e81089c309fb21f8f7d021d86689450083c5024a85d20f85cfffffffec37755d7a0528ed24ed24ed0b887feb509838f95c962b9670fec6ffc6ff9f321f581e00d380'






