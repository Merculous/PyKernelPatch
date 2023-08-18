
from .file import readBinaryFile, writeBinaryFile
from .find import findOffsets
from .utils import formatBytes


def patchOffset(old, new, offset, data):
    i = int(offset[2:], 16)

    pattern_len = len(old)

    buffer = data[i:i+pattern_len]

    offsets_found = 0

    if old in buffer:
        print(f'Found pattern at offset: {offset}')

        new_buffer = buffer.replace(old, new)

        old_hex = formatBytes(old)
        new_hex = formatBytes(new)

        # FIXME
        print(f'Patching: {old_hex} to {new_hex}')

        data[i:i+pattern_len] = new_buffer

        offsets_found += 1

    return offsets_found


def patchCSEnforcement(info, data):
    patched = 0

    for offset in info:
        pattern = info[offset]
        new_pattern = pattern.replace(b'\x1b\x68', b'\x01\x23')

        offsets_patched = patchOffset(pattern, new_pattern, offset, data)

        patched += offsets_patched

    return patched


def patchAMFIMemcmp(info, data):
    patched = 0

    for offset in info:
        pattern = info[offset]
        new_pattern = pattern.replace(b'\xd0\x47', b'\x00\x20')

        offsets_patched = patchOffset(pattern, new_pattern, offset, data)

        patched += offsets_patched

    return patched


def patchPE_i_can_has_debugger(info, data):
    patched = 0

    for offset in info:
        pattern = info[offset]
        new_pattern = pattern.replace(b'\xe0\x47', b'\x00\x20')

        offsets_patched = patchOffset(pattern, new_pattern, offset, data)

        patched += offsets_patched

    return patched


def patchAppleImage3NORAccess(info, data):
    patched = 0

    for offset in info:
        pattern = info[offset]

        if b'\x00\x28' in pattern:
            new_pattern = pattern.replace(b'\x00\x28', b'\x00\x20')

        elif b'\xb0\x47' in pattern:
            new_pattern = pattern.replace(b'\xb0\x47', b'\x01\x20')

        elif b'\x08\x46' in pattern:
            new_pattern = pattern.replace(b'\x08\x46', b'\x00\x20')

        offsets_patched = patchOffset(pattern, new_pattern, offset, data)

        patched += offsets_patched

    return patched


def patchKernel(orig, patched):
    data = readBinaryFile(orig)

    # This will be the data we modify
    new_data = bytearray(data[:])

    offsets = findOffsets(orig)

    offsets_possible = 8

    patch_count1 = patchCSEnforcement(offsets['cs_enforcement'], new_data)
    patch_count2 = patchAMFIMemcmp(offsets['amfi_memcmp'], new_data)
    patch_count3 = patchPE_i_can_has_debugger(offsets['pe_i_can_has_debugger'], new_data)
    patch_count4 = patchAppleImage3NORAccess(offsets['apple_image3_nor_access'], new_data)

    # new_data should be patched now

    offsets_found = patch_count1 + patch_count2 + patch_count3 + patch_count4

    if offsets_found != offsets_possible:
        print(f'Found {offsets_found}/{offsets_possible} offsets!')
    else:
        print('Found all offsets!')

    writeBinaryFile(new_data, patched)
