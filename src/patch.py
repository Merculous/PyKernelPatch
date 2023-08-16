
from .file import readBinaryFile, writeBinaryFile
from .find import findOffsets
from .utils import convertHexToBytes, formatBytes


def patchKernel(orig, patched):
    data = readBinaryFile(orig)

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
    else:
        print('Found all offsets!')

    writeBinaryFile(new_data, patched)
