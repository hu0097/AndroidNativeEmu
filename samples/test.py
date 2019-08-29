# -*- coding: utf-8 -*-

from unicorn import *
from unicorn.arm_const import *

ARM_CODE   = b"\x37\x00\xa0\xe3\x03\x10\x42\xe0" 
# mov r0, #0x37; 
# sub r1, r2, r3

# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))

# Test ARM
def test_arm():
    print("Emulate ARM code")
    
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

    ADDRESS = 0x10000
    mu.mem_map(ADDRESS, 2 * 0x10000)

    mu.mem_write(ADDRESS, ARM_CODE)
    
    mu.reg_write(UC_ARM_REG_R0, 0x1234)
    mu.reg_write(UC_ARM_REG_R2, 0x6789)
    mu.reg_write(UC_ARM_REG_R3, 0x3333)

    mu.hook_add(UC_HOOK_CODE, hook_code, begin=ADDRESS, end=ADDRESS)

    # emulate machine code in infinite time
    mu.emu_start(ADDRESS, ADDRESS + len(ARM_CODE))

    r0 = mu.reg_read(UC_ARM_REG_R0)
    r1 = mu.reg_read(UC_ARM_REG_R1)
    r2 = mu.reg_read(UC_ARM_REG_R2)
    r3 = mu.reg_read(UC_ARM_REG_R3)
    print(">>> R0 = 0x%x" % r0)
    print(">>> R1 = 0x%x" % r1)
    print(">>> R2 = 0x%x" % r2)
    print(">>> R3 = 0x%x" % r3)

test_arm()


