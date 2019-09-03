from unicorn import *
from unicorn.x86_const import *
import struct


def read(name):
    with open(name, 'rb') as f:
        return f.read()

def u32(data):
    return struct.unpack("I", data)[0]

def p32(num):
    return struct.pack("I", num)

def hook_code(mu, address, size, user_data):
    instruction = mu.mem_read(address, size)
    instruction_str = ''.join('{:02x} '.format(x) for x in instruction)
    print('# Tracing instruction at 0x%x, instruction size = 0x%x, instruction = %s' % (address, size, instruction_str))


mu = Uc(UC_ARCH_X86, UC_MODE_32)

BASE = 0x80000
STACK_ADDR = 0x0
STACK_SIZE = 3 * 0x10000

mu.mem_map(STACK_ADDR, STACK_SIZE)
mu.mem_map(BASE, STACK_SIZE)

print(read("./function"))
mu.mem_write(BASE, read("./function"))
r_esp = STACK_ADDR + int(STACK_SIZE/2)     #ESP points to this address at function call


print(r_esp)
print(hex(r_esp))
STRING_ADDR = 0x0
# print(u32("batmanx00".encode()))
mu.mem_write(STRING_ADDR, "batmanx00".encode()) #write "batman" somewhere. We have choosen an address 0x0 which belongs to the stack.

print(p32(5))
mu.reg_write(UC_X86_REG_ESP, r_esp)     #set ESP
mu.mem_write(r_esp+4, p32(5))           #set the first argument. It is integer 5
mu.mem_write(r_esp+8, p32(STRING_ADDR)) #set the second argument. This is a pointer to the string "batman"

mu.hook_add(UC_HOOK_CODE, hook_code)

mu.emu_start(0x8057b, 0x805AB)      #start emulation from the beginning of super_function, end at RET instruction
return_value = mu.reg_read(UC_X86_REG_EAX)
print(return_value)
print("The returned value is: %d" % return_value)


