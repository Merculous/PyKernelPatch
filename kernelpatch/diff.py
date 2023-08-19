
from .file import readBinaryFile


def createDiff(orig, patched):
    orig_data = readBinaryFile(orig)
    patched_data = readBinaryFile(patched)

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
