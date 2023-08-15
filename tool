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

kernel_versions = {
    '5.0.1': '1878.4.46~1',
    '5.1': '1878.11.8~1',
    '5.1.1': '1878.11.10~1'
}


def readKernel(kernel):
    with open(kernel, 'rb') as f:
        data = f.read()
        return data


def findPattern(pattern, data):
    # TODO
    # Make this function be able to adjust a few bytes
    # (look back and ahead a few bytes) so that it can
    # actually find a pattern besides just looking for
    # an exact match. This makes me need to adjust bytes
    # for offsets even though the pattern is a few bytes
    # different or off from position.

    data_len = len(data)
    pattern_len = len(pattern)

    for i in range(0, data_len, pattern_len):
        # look_back = data[i-4:i]

        buffer = data[i:i+pattern_len]

        # look_ahead = data[i+pattern_len+4:i+pattern_len+8]

        # I guess I could just add in the look_back or look_ahead
        # to a copy of the buffer and then check with that if the
        # buffer did not work. I will obviously have to make sure
        # that I adjust the offset based on the size of the look_x
        # buffer, which atm is just 4 bytes.

        if pattern == buffer:
            return hex(i)


def convertHexToBytes(data):
    return bytes.fromhex(data)


def formatBytes(data):
    return binascii.hexlify(data).decode('utf-8')


def getKernelVersion(data):
    search = b'Darwin Kernel Version'

    possible = (
        b'10.3.1',
        b'10.4.0',
        b'11.0.0',
        b'13.0.0',
        b'14.0.0',
        b'15.0.0',
        b'15.6.0',
        b'16.0.0',
        b'16.1.0',
        b'16.3.0',
        b'16.5.0',
        b'16.6.0',
        b'16.7.0'
    )

    days = (
        b'Mon',
        b'Tue',
        b'Wed',
        b'Thu',
        b'Fri',
        b'Sat',
        b'Sun'
    )

    version_string = None
    version_string_offset = None

    for version in possible:
        version_string1 = search + b' ' + version

        match1 = findPattern(version_string1, data)

        if match1:
            version_string = version_string1
            version_string_offset = match1
            break

        for day in days:
            version_string2 = search + b' ' + version + b': ' + day[:1]

            match2 = findPattern(version_string2, data)

            version_string3 = search + b' ' + version + b': ' + day[:2]

            match3 = findPattern(version_string3, data)

            if match2:
                version_string = version_string2
                version_string_offset = match2
                break

            elif match3:
                version_string = version_string3
                version_string_offset = match3
                break

    if not version_string:
        raise Exception('Could not find kernel version string!')

    extra = len(version_string) + 75

    i = int(version_string_offset[2:], 16)

    buffer = data[i:i+extra]

    buffer_hex = formatBytes(buffer)
    buffer_X_index = buffer_hex.index('58')

    new_buffer_hex = buffer_hex[:buffer_X_index+2]
    new_buffer_hex_end = new_buffer_hex[buffer_X_index:]

    new_buffer = convertHexToBytes(new_buffer_hex)

    if new_buffer_hex_end != '58':
        raise Exception(f'Failed extracting kernel version. Got buffer: {buffer}')

    kernel_version = new_buffer.split(b';')[1].split(b'-')[1].split(b'/')[0].decode('utf-8')

    results = (
        hex(len(new_buffer)),
        version_string_offset,
        hex(i + extra),
        new_buffer,
        kernel_version
    )

    return results


def findCSEnforcement(data, version):
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

    search = {
        '5.0.1': [
            {
                'pattern': b'\xa2\x6a\x1b\x68',
                'old': b'\x1b\x68',
                'new': b'\x01\x23'
            }
        ],
        '5.1.1': [
            {
                'pattern': b'\xa2\x6a\x1b\x68',
                'old': b'\x1b\x68',
                'new': b'\x01\x23'
            }
        ]
    }

    info = {}

    for option in search:
        if option == version:
            for patch in search[version]:
                offset = findPattern(patch['pattern'], data)

                if offset:
                    match = {offset: patch}

                    info.update(match)

    if info:
        return info
    else:
        return None


def findAMFIMemcmp(data, version):
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

    search = {
        '5.0.1': [
            {
                'pattern': b'\x29\x46\x13\x22\xd0\x47\x01',
                'old': b'\xd0\x47',
                'new': b'\x00\x20'
            }
        ],
        '5.1.1': [
            {
                'pattern': b'\x29\x46\x13\x22\xd0\x47',
                'old': b'\xd0\x47',
                'new': b'\x00\x20'
            }
        ]
    }

    info = {}

    for option in search:
        if option == version:
            for patch in search[version]:
                offset = findPattern(patch['pattern'], data)

                if offset:
                    match = {offset: patch}

                    info.update(match)

    if info:
        return info
    else:
        return None


def findPE_i_can_has_debugger(data, version):
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

    search = {
        '5.0.1': [
            {
                'pattern': b'\x00\x80\xcd\xf8\x04\x80\x02\x93\xe0\x47\xc0\xbb',
                'old': b'\xe0\x47',
                'new': b'\x00\x20'
            },
            {
                'pattern': b'\xe0\x47\x00\x28\x18\xbf\x4f\xf0\x01\x08\x40\x46\x05\xb0',
                'old': b'\xe0\x47',
                'new': b'\x00\x20'
            }
        ],
        '5.1.1': [
            {
                'pattern': b'\x01\x22\xcd\xf8\x00\x80\xcd\xf8\x04\x80\x02\x93\xe0\x47\xc0',
                'old': b'\xe0\x47',
                'new': b'\x00\x20'
            },
            {
                'pattern': b'\xcd\xf8\x04\x80\xcd\xf8\x08\x80\xe0\x47\x00\x28\x18',
                'old': b'\xe0\x47',
                'new': b'\x00\x20'
            }
        ]
    }

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

    info = {}

    for option in search:
        if option == version:
            for patch in search[version]:
                offset = findPattern(patch['pattern'], data)

                if offset:
                    match = {offset: patch}

                    info.update(match)

    if info:
        return info
    else:
        return None


def findAppleImage3NORAccess(data, version):
    '''
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDFE6 05 98                       LDR             R0, [SP,#0x30+var_1C]
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDFE8 02 21                       MOVS            R1, #2
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDFEA 85 4C                       LDR             R4, =(sub_808BE944+1)
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDFEC A0 47                       BLX             R4      ; sub_808BE944
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDFEE 00 28                       CMP             R0, #0  ; 00 28 -> 00 20
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BDFF0 F2 D1                       BNE             loc_808BDFD8
    '''

    # 808BDFEE 87afef _memcpy AppleImage3NORAccess LLB

    search = {
        '5.0.1': [
            {
                'pattern': b'\x02\x21\x85\x4c\xa0\x47\x00\x28',
                'old': b'\x00\x28',
                'new': b'\x00\x20'
            },
            {
                'pattern': b'\xf2\xd1\x05\x98\x83\x4c\xa0\x47\x00\x28\xed\xd1',
                'old': b'\x00\x28',
                'new': b'\x00\x20'
            },
            {
                'pattern': b'\x2b\x4e\x28\x46\x02\x99\xb0\x47',
                'old': b'\xb0\x47',
                'new': b'\x01\x20'
            },
            {
                'pattern': b'\x4f\xf0\xff\x31\xa7\xf1\x18\x04\x08\x46\xa5\x46\xbd\xe8\x00\x0d\xf0',
                'old': b'\x08\x46',
                'new': b'\x00\x20'
            }
        ],
        '5.1.1': [
            {
                'pattern': b'\x02\x21\x85\x4c\xa0\x47\x00\x28',
                'old': b'\x00\x28',
                'new': b'\x00\x20'
            },
            {
                'pattern': b'\xf2\xd1\x05\x98\x83\x4c\xa0\x47\x00\x28',
                'old': b'\x00\x28',
                'new': b'\x00\x20'
            },
            {
                'pattern': b'\x2b\x4e\x28\x46\x02\x99\xb0\x47',
                'old': b'\xb0\x47',
                'new': b'\x01\x20'
            },
            {
                'pattern': b'\xa7\xf1\x18\x04\x08\x46\xa5\x46\xbd\xe8',
                'old': b'\x08\x46',
                'new': b'\x00\x20'
            }
        ]
    }

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

    '''
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BE180 2B 4E                       LDR             R6, =(sub_808BD868+1)
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BE182 28 46                       MOV             R0, R5
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BE184 02 99                       LDR             R1, [SP,#0x30+address]
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BE186 B0 47                       BLX             R6      ; sub_808BD868 ; B0 47 -> 01 20
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BE188 00 28                       CMP             R0, #0
    '''

    # 808BE186 87b186 _memcpy AppleImage3NORAccess

    '''
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BF292 A7 F1 18 04                 SUB.W           R4, R7, #-var_18
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BF296 08 46                       MOV             R0, R1  ; 08 46 -> 00 20
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BF298 A5 46                       MOV             SP, R4
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BF29A BD E8 00 0D                 POP.W           {R8,R10,R11}
    com.apple.driver.AppleImage3NORAccess:__TEXT_hidden:808BF29E F0 BD                       POP             {R4-R7,PC}
    '''

    # 808BF296 87c296 _memcmp AppleImage3NORAccess

    info = {}

    for option in search:
        if option == version:
            for patch in search[version]:
                offset = findPattern(patch['pattern'], data)

                if offset:
                    match = {offset: patch}

                    info.update(match)

    if info:
        return info
    else:
        return None


def writeJSON(data, path):
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)


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
    return diff_cleaned


def findOffsets(path):
    data = readKernel(path)

    version_string = getKernelVersion(data)

    for version in kernel_versions:
        kernel_string = kernel_versions[version]

        if version_string[-1] == kernel_string:
            break

    offsets = (
        findCSEnforcement(data, version),
        findAMFIMemcmp(data, version),
        findPE_i_can_has_debugger(data, version),
        findAppleImage3NORAccess(data, version)
    )

    info = {}

    for part in offsets:
        if part:
            info.update(part)

    if info:
        return info
    else:
        raise Exception('No offsets were found!')


def writeBinaryFile(data, path):
    with open(path, 'wb') as f:
        f.write(data)


def patchKernel(orig, patched):
    data = readKernel(orig)

    # This will be the data we modify
    new_data = bytearray(data[:])

    offsets = findOffsets(orig)

    offsets_found = 0
    offsets_possible = 8

    for offset in offsets:
        pattern = formatBytes(offsets[offset]['pattern'])
        old = formatBytes(offsets[offset]['old'])
        new = formatBytes(offsets[offset]['new'])

        pattern_len = len(pattern)

        for i in range(len(data)):
            i_hex = hex(i)

            if i_hex == offset:
                buffer = data[i:i+pattern_len]
                buffer_hex = formatBytes(buffer)

                if pattern in buffer_hex:
                    offsets_found += 1

                    print(f'Found pattern at offset: {i_hex}')

                    new_data_hex = buffer_hex.replace(old, new)
                    new_data_bytes = convertHexToBytes(new_data_hex)

                    print(f'Patching: {old} to {new}')

                    new_data[i:i+pattern_len] = new_data_bytes

    if offsets_found != offsets_possible:
        print(f'Found {offsets_found}/{offsets_possible} offsets!')

    writeBinaryFile(new_data, patched)


def writeOffsetsToJSON(kernel, path):
    offsets = findOffsets(kernel)

    offsets_formatted = offsets.copy()

    for offset in offsets:
        for k, v in offsets[offset].items():
            offsets_formatted[offset][k] = formatBytes(v)

    writeJSON(offsets_formatted, path)


def main():
    parser = ArgumentParser()

    parser.add_argument('--orig', nargs=1)
    parser.add_argument('--patched', nargs=1)
    parser.add_argument('--find', action='store_true')
    parser.add_argument('--diff', action='store_true')
    parser.add_argument('--patch', action='store_true')

    parser.add_argument('--test', action='store_true')

    args = parser.parse_args()

    if args.find:
        if args.orig and not args.patched:
            writeOffsetsToJSON(args.orig[0], 'offsets.json')

    elif args.diff:
        if args.orig and args.patched:
            diff = diffKernels(args.orig[0], args.patched[0])
            writeJSON(diff, 'diff.json')

    elif args.patch:
        if args.orig and args.patched:
            patchKernel(args.orig[0], args.patched[0])

    elif args.test:
        data = readKernel(args.orig[0])
        getKernelVersion(data)

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
