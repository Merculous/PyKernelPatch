#!/usr/bin/env python3

import binascii
import json
from argparse import ArgumentParser

'''
80045876 44876 CS_Enforcement [_kernel_pmap, vm_page] vm_fault_enter
80553718 510718 AMFI::_memcmp CS_Enforcement
808BDB24 87ab24 debug_enabled PE_i_can_has_debugger AppleImage3NORAccess
808BDB90 87ab90 debug_enabled PE_i_can_has_debugger AppleImage3NORAccess
808BDFEE 87afef _memcpy AppleImage3NORAccess LLB
808BDFF8 87aff9 _memcpy AppleImage3NORAccess LLB
808BE186 87b186 _memcpy AppleImage3NORAccess
808BF296 87c296 _memcmp AppleImage3NORAccess

cs_enforcement RWX
Patch AMFI::_memcmp to return 0
PE_i_can_has_debugger debug_enabled Enabled unsigned binaries and some other stuff
Allow copying unsigned memory?
Patch out something with above?
'''


def readKernel(kernel):
    with open(kernel, 'rb') as f:
        data = f.read()

    # hex_data = binascii.hexlify(data).decode('utf-8')
    # return hex_data

    return data


def findPattern(pattern, data):
    matches = []

    data_len = len(data)
    pattern_len = len(pattern)

    for i in range(0, data_len, pattern_len):
        buffer = data[i:i+pattern_len]

        if pattern == buffer:
            matches.append(i)

    matches = [hex(m) for m in matches]
    return matches


def findCSEnforcement(data):
    '''
    __TEXT:__text:8004586C DF F8 88 33                 LDR.W           R3, =dword_802DF338
    __TEXT:__text:80045870 1D EE 90 0F                 MRC             p15, 0, R0,c13,c0, 4
    __TEXT:__text:8004586C DF F8 88 33                 LDR.W           R3, =dword_802DF338
    __TEXT:__text:80045870 1D EE 90 0F                 MRC             p15, 0, R0,c13,c0, 4
    __TEXT:__text:80045874 A2 6A                       LDR             R2, [R4,#0x28]
    __TEXT:__text:80045876 1B 68                       LDR             R3, [R3] ; 1B 68 -> 01 23
    __TEXT:__text:80045878 00 2B                       CMP             R3, #0
    __TEXT:__text:8004587A 04 BF                       ITT EQ
    '''

    # uint8_t CodeSignEnforcement[] = {0xa2, 0x6a, 0x1b, 0x68, 0x00, 0x2b, 0x04, 0xbf};

    # 80045876 44876 CS_Enforcement [_kernel_pmap, vm_page] vm_fault_enter

    search = b'\xa2\x6a\x1b\x68'
    matches = findPattern(search, data)
    return [search, matches]


def findAMFIMemcmp(data):
    '''
    com.apple.driver.AppleMobileFileIntegrity:__text:80553712             loc_80553712                            ; CODE XREF: sub_805536E4+4A↓j
    com.apple.driver.AppleMobileFileIntegrity:__text:80553712 20 46                       MOV             R0, R4  ; __s1
    com.apple.driver.AppleMobileFileIntegrity:__text:80553714 29 46                       MOV             R1, R5  ; __s2
    com.apple.driver.AppleMobileFileIntegrity:__text:80553716 13 22                       MOVS            R2, #0x13 ; __n
    com.apple.driver.AppleMobileFileIntegrity:__text:80553718 D0 47                       BLX             R10     ; _memcmp ; D0 47 -> 00 20
    com.apple.driver.AppleMobileFileIntegrity:__text:8055371A 01 21                       MOVS            R1, #1
    com.apple.driver.AppleMobileFileIntegrity:__text:8055371C 40 B1                       CBZ             R0, loc_80553730
    '''

    # 80553718 510718 AMFI::_memcmp CS_Enforcement

    search = b'\x29\x46\x13\x22\xd0\x47'
    matches = findPattern(search, data)
    return [search, matches]


def findPE_i_can_has_debugger(data):
    '''
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDAF0 01 22                       MOVS            R2, #1
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDAF2 CD F8 00 80                 STR.W           R8, [SP,#0x2C+fromEntry]
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDAF6 CD F8 04 80                 STR.W           R8, [SP,#0x2C+var_28]
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDAFA 02 93                       STR             R3, [SP,#0x2C+var_24]
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDAFC E0 47                       BLX             R12     ; sub_808BD904

    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDAFE 00 28                       CMP             R0, #0
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDB00 4B D1                       BNE             loc_808BDB9A
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDB02 8D B9                       CBNZ            R5, loc_808BDB28
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDB04 44 F6 44 71                 MOVW            R1, #0x4F44
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDB08 4F F0 01 08                 MOV.W           R8, #1
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDB0C 00 23                       MOVS            R3, #0
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDB0E C5 F2 52 01                 MOVT            R1, #0x5052
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDB12 DF F8 C4 C0                 LDR.W           R12, =(sub_808BD904+1)
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDB16 20 46                       MOV             R0, R4

    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDB18 01 22                       MOVS            R2, #1
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDB1A CD F8 00 80                 STR.W           R8, [SP,#0x2C+fromEntry]
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDB1E CD F8 04 80                 STR.W           R8, [SP,#0x2C+var_28]
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDB22 02 93                       STR             R3, [SP,#0x2C+var_24]
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDB24 E0 47                       BLX             R12     ; sub_808BD904 ; E0 47 -> 00 20
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDB26 C0 BB                       CBNZ            R0, loc_808BDB9A
    '''

    # 808BDB24 87ab24 debug_enabled PE_i_can_has_debugger AppleImage3NORAccess

    search1 = b'\x01\x22\xcd\xf8\x00\x80\xcd\xf8\x04\x80\x02\x93\xe0\x47\xc0'
    matches1 = findPattern(search1, data)

    '''
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDB7A DF F8 68 C0                 LDR.W           R12, =(sub_808BD904+1)
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDB7E 20 46                       MOV             R0, R4
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDB80 5A 46                       MOV             R2, R11
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDB82 03 9B                       LDR             R3, [SP,#0x2C+var_20]
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDB84 CD F8 00 80                 STR.W           R8, [SP,#0x2C+fromEntry]
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDB88 CD F8 04 80                 STR.W           R8, [SP,#0x2C+var_28]
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDB8C CD F8 08 80                 STR.W           R8, [SP,#0x2C+var_24]
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDB90 E0 47                       BLX             R12     ; sub_808BD904 ; E0 47 -> 00 20
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDB92 00 28                       CMP             R0, #0
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDB94 18 BF                       IT NE
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDB96 4F F0 01 08                 MOVNE.W         R8, #1
    '''

    # 808BDB90 87ab90 debug_enabled PE_i_can_has_debugger AppleImage3NORAccess

    search2 = b'\xcd\xf8\x04\x80\xcd\xf8\x08\x80\xe0\x47\x00\x28\x18'
    matches2 = findPattern(search2, data)

    return [[search1, matches1], [search2, matches2]]


def findAppleImage3NORAccess(data):
    '''
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDFE6 05 98                       LDR             R0, [SP,#0x30+var_1C]
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDFE8 02 21                       MOVS            R1, #2
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDFEA 85 4C                       LDR             R4, =(sub_808BE944+1)
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDFEC A0 47                       BLX             R4      ; sub_808BE944
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDFEE 00 28                       CMP             R0, #0  ; 00 28 -> 00 20
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDFF0 F2 D1                       BNE             loc_808BDFD8
    '''

    # 808BDFEE 87afef _memcpy AppleImage3NORAccess LLB

    search1 = b'\x02\x21\x85\x4c\xa0\x47\x00\x28'
    matches1 = findPattern(search1, data)

    '''
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDFF2 05 98                       LDR             R0, [SP,#0x30+var_1C]
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDFF4 83 4C                       LDR             R4, =(sub_808BD9F4+1)
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDFF6 A0 47                       BLX             R4      ; sub_808BD9F4
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDFF8 00 28                       CMP             R0, #0  ; 00 28 -> 00 20
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDFFA ED D1                       BNE             loc_808BDFD8
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDFFC 30 46                       MOV             R0, R6
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDFFE 44 7C                       LDRB            R4, [R0,#0x11]
    '''

    # 808BDFF8 87aff9 _memcpy AppleImage3NORAccess LLB

    search2 = b'\xf2\xd1\x05\x98\x83\x4c\xa0\x47\x00\x28'
    matches2 = findPattern(search2, data)

    '''
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BE180 2B 4E                       LDR             R6, =(sub_808BD868+1)
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BE182 28 46                       MOV             R0, R5
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BE184 02 99                       LDR             R1, [SP,#0x30+address]
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BE186 B0 47                       BLX             R6      ; sub_808BD868 ; B0 47 -> 01 20
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BE188 00 28                       CMP             R0, #0
    '''

    # 808BE186 87b186 _memcpy AppleImage3NORAccess

    search3 = b'\x2b\x4e\x28\x46\x02\x99\xb0\x47'
    matches3 = findPattern(search3, data)

    '''
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BF292 A7 F1 18 04                 SUB.W           R4, R7, #-var_18
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BF296 08 46                       MOV             R0, R1  ; 08 46 -> 00 20
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BF298 A5 46                       MOV             SP, R4
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BF29A BD E8 00 0D                 POP.W           {R8,R10,R11}
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BF29E F0 BD                       POP             {R4-R7,PC}
    '''

    # 808BF296 87c296 _memcmp AppleImage3NORAccess

    search4 = b'\xa7\xf1\x18\x04\x08\x46\xa5\x46\xbd\xe8'
    matches4 = findPattern(search4, data)

    return [[search1, matches1], [search2, matches2], [search3, matches3], [search4, matches4]]


def writeJSON(data, path):
    with open(path, 'w') as f:
        json.dump(data, f)


def formatBytes(data):
    return binascii.hexlify(data).decode('utf-8')


def writeOffsets(offsets):
    pass


def main():
    parser = ArgumentParser()

    parser.add_argument('-i', nargs=1)

    args = parser.parse_args()

    if args.i:
        data = readKernel(args.i[0])
        offsets = [
            findCSEnforcement(data),
            findAMFIMemcmp(data),
            findPE_i_can_has_debugger(data),
            findAppleImage3NORAccess(data)
        ]
        writeOffsets(offsets)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
