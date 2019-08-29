# -*- coding: utf-8 -*-

from unicorn import *
from unicorn.arm_const import *

ARM_CODE   = b"\x37\x00\xa0\xe3\x03\x10\x42\xe0" 
# mov r0, #0x37; 
# sub r1, r2, r3

# Test ARM
def test_arm():
    print("Emulate ARM code")
    
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

    ADDRESS = 0x10000
    mu.mem_write(ADDRESS, ARM_CODE)
    
    mu.reg_write(UC_ARM_REG_R0, 0x1234)
    mu.reg_write(UC_ARM_REG_R2, 0x6789)
    mu.reg_write(UC_ARM_REG_R3, 0x3333)


test_arm()


