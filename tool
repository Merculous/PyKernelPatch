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
        return data


def findPattern(pattern, data):
    data_len = len(data)
    pattern_len = len(pattern)

    for i in range(0, data_len, pattern_len):
        buffer = data[i:i+pattern_len]

        if pattern == buffer:
            return hex(i)


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
    match = findPattern(search, data)

    info = {
        match: {
            'pattern': formatBytes(search)
        }
    }

    return info


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
    match = findPattern(search, data)

    info = {
        match: {
            'pattern': formatBytes(search)
        }
    }

    return info


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
    match1 = findPattern(search1, data)

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
    match2 = findPattern(search2, data)

    info = {
        match1: {
            'pattern': formatBytes(search1)
        },
        match2: {
            'pattern': formatBytes(search2)
        }
    }

    return info


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
    match1 = findPattern(search1, data)

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
    match2 = findPattern(search2, data)

    '''
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BE180 2B 4E                       LDR             R6, =(sub_808BD868+1)
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BE182 28 46                       MOV             R0, R5
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BE184 02 99                       LDR             R1, [SP,#0x30+address]
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BE186 B0 47                       BLX             R6      ; sub_808BD868 ; B0 47 -> 01 20
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BE188 00 28                       CMP             R0, #0
    '''

    # 808BE186 87b186 _memcpy AppleImage3NORAccess

    search3 = b'\x2b\x4e\x28\x46\x02\x99\xb0\x47'
    match3 = findPattern(search3, data)

    '''
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BF292 A7 F1 18 04                 SUB.W           R4, R7, #-var_18
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BF296 08 46                       MOV             R0, R1  ; 08 46 -> 00 20
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BF298 A5 46                       MOV             SP, R4
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BF29A BD E8 00 0D                 POP.W           {R8,R10,R11}
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BF29E F0 BD                       POP             {R4-R7,PC}
    '''

    # 808BF296 87c296 _memcmp AppleImage3NORAccess

    search4 = b'\xa7\xf1\x18\x04\x08\x46\xa5\x46\xbd\xe8'
    match4 = findPattern(search4, data)

    info = {
        match1: {
            'pattern': formatBytes(search1)
        },
        match2: {
            'pattern': formatBytes(search2)
        },
        match3: {
            'pattern': formatBytes(search3)
        },
        match4: {
            'pattern': formatBytes(search4)
        }
    }

    return info


def writeJSON(data, path):
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)


def formatBytes(data):
    return binascii.hexlify(data).decode('utf-8')


def createDiff(orig, patched):
    orig_data = readKernel(orig)
    patched_data = readKernel(patched)

    orig_len = len(orig_data)
    patched_len = len(patched_data)

    if orig_len != patched_len:
        raise Exception('Kernels are not the same size!')

    info = {}

    for i in range(orig_len):
        orig_byte = orig_data[i]
        patched_byte = patched_data[i]

        i_hex = hex(i)

        if orig_byte != patched_byte:
            orig_hex = hex(orig_byte)[2:]
            patched_hex = hex(patched_byte)[2:]

            orig_hex_len = len(orig_hex)
            patched_hex_len = len(patched_hex)

            if orig_hex_len == 1:
                orig_hex = '0' + orig_hex

            if patched_hex_len == 1:
                patched_hex = '0' + patched_hex

            info[i_hex] = {
                'orig': orig_hex,
                'patched': patched_hex
            }

    return info


def cleanUpDiff(info):
    cleaned = {}

    offsets = iter([o for o in info])

    for offset in offsets:
        offset_orig = info[offset]['orig']
        offset_patched = info[offset]['patched']

        try:
            next_offset = next(offsets)
            next_offset_orig = info[next_offset]['orig']
            next_offset_patched = info[next_offset]['patched']
        except StopIteration:
            break

        offset_int = int(offset[2:], 16)
        next_offset_int = int(next_offset[2:], 16)

        new_offset = offset
        orig_hex = offset_orig
        patched_hex = offset_patched

        if offset_int + 1 == next_offset_int:
            orig_hex += next_offset_orig
            patched_hex += next_offset_patched

            cleaned[new_offset] = {
                'orig': orig_hex,
                'patched': patched_hex
            }

        else:
            cleaned[offset] = {
                'orig': orig_hex,
                'patched': patched_hex
            }

            # Gotta do below as I'm using an iterable.
            # If I don't, only above will be added.

            cleaned[next_offset] = {
                'orig': next_offset_orig,
                'patched': next_offset_patched
            }

    return cleaned


def diffKernels(orig, patched):
    diff = createDiff(orig, patched)
    diff_cleaned = cleanUpDiff(diff)
    return json.loads(diff_cleaned)


def findOffsets(path):
    data = readKernel(path)

    offsets = (
        findCSEnforcement(data),
        findAMFIMemcmp(data),
        findPE_i_can_has_debugger(data),
        findAppleImage3NORAccess(data)
    )

    info = {}

    for part in offsets:
        info.update(part)

    return json.loads(info)


def main():
    parser = ArgumentParser()

    parser.add_argument('--orig', nargs=1)
    parser.add_argument('--patched', nargs=1)
    parser.add_argument('--find', action='store_true')

    args = parser.parse_args()

    if args.orig and args.find:
        if not args.patched:
            offsets = findOffsets(args.orig[0])
            writeJSON(offsets, 'offsets.json')

        else:
            diff = diffKernels(args.orig[0], args.patched[0])
            writeJSON(diff, 'diff.json')

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
