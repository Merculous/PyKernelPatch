
from .file import readBinaryFile
from .patterns import Pattern
from .utils import convertHexToBytes, formatBytes

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
    '5.x': {
        '5.0': '1878.4.43~2',
        '5.0.1': '1878.4.46~1',
        '5.1': '1878.11.8~1',
        '5.1.1': '1878.11.10~1'
    }
}

# 80043000


def findPattern(pattern, data, look_back=4, look_ahead=4):
    data_len = len(data)
    pattern_len = len(pattern)

    found = None

    for i in range(0, data_len, pattern_len):
        look_back_buffer = data[i-look_back:i]

        buffer = data[i:i+pattern_len]

        look_ahead_buffer = data[i+pattern_len:i+pattern_len+look_ahead]

        window = look_back_buffer + buffer + look_ahead_buffer

        if pattern == buffer:
            found = hex(i)

        # TODO
        # Actually add the dynamic nature of look_back and look_ahead

        else:
            if pattern in window:
                found = hex(i-look_back)
            else:
                window = b''

    if found:
        return found
    else:
        return None


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

    # Need to check that the buffer doesn't contain garbage data

    extra = len(version_string) + 75

    i = int(version_string_offset[2:], 16)

    buffer_end = i + extra

    buffer = data[i:buffer_end]

    buffer_hex = formatBytes(buffer)

    version_string_hex = formatBytes(version_string)
    version_string_index = buffer_hex.index(version_string_hex)

    new_buffer_hex = buffer_hex[version_string_index:]

    if not new_buffer_hex.startswith(version_string_hex):
        raise Exception('Buffer does not start with kernel version string!')

    new_i_hex = hex(buffer_end + 8)
    new_i = int(new_i_hex[2:], 16)

    start = i + version_string_index // 2
    start_hex = hex(start)

    new_buffer = data[start:new_i]
    new_buffer_hex = formatBytes(new_buffer)

    new_buffer_X_index = new_buffer_hex.index('58')

    new_buffer_hex = new_buffer_hex[:new_buffer_X_index+2]
    new_buffer_hex_end = new_buffer_hex[new_buffer_X_index:]

    new_buffer = convertHexToBytes(new_buffer_hex)
    new_buffer_len = len(new_buffer)

    if new_buffer_hex_end != '58':
        raise Exception(f'Failed extracting kernel version. Got buffer: {buffer}')

    kernel_version = new_buffer.split(b';')[1].split(b'-')[1].split(b'/')[0].decode('utf-8')

    results = (
        hex(new_buffer_len),
        start_hex,
        hex(start + new_buffer_len),
        new_buffer,
        kernel_version
    )

    print(f'Found kernel version string: {results[3].decode("utf-8")}')

    return results


def findPatchOffset(patterns, data):
    info = {}

    for pattern in patterns:
        offset = findPattern(pattern, data)

        if offset:
            match = {offset: pattern}

            info.update(match)

    if info:
        return info
    else:
        return None


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

    search = Pattern(version).CSEnforcement()
    offsets = findPatchOffset(search, data)

    info = {'cs_enforcement': offsets}
    return info


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

    search = Pattern(version).AMFIMemcmp()
    offsets = findPatchOffset(search, data)

    info = {'amfi_memcmp': offsets}
    return info


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

    search = Pattern(version).PE_i_can_has_debugger()
    offsets = findPatchOffset(search, data)

    info = {'pe_i_can_has_debugger': offsets}
    return info


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

    search = Pattern(version).AppleImage3NORAccess()
    offsets = findPatchOffset(search, data)

    info = {'apple_image3_nor_access': offsets}
    return info


def findOffsets(path):
    data = readBinaryFile(path)

    version_string = getKernelVersion(data)

    for major in kernel_versions:
        for version in kernel_versions[major]:
            if version_string[-1] == kernel_versions[major][version]:
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
