
from .find import Find
from .utils import formatBytes, hexStringToHexInt


class Patch(Find):
    def __init__(self, data):
        super().__init__(data)

        self.patched_data = bytearray(self.data[:])

    def patchData(self, offset, pattern, old, new):
        i = hexStringToHexInt(offset)

        pattern_len = len(pattern)

        buffer = self.patched_data[i:i+pattern_len]

        if buffer == pattern:
            old_i = buffer.index(old)

            real_offset = hex(hexStringToHexInt(offset) + old_i)

            new_buffer = buffer.replace(old, new)
            self.patched_data[i:i+pattern_len] = new_buffer

            old_hex = formatBytes(old)
            new_hex = formatBytes(new)

            print(f'{real_offset}: {old_hex} -> {new_hex}')

    def patch_CSEnforcement(self, offsets):
        for offset, pattern in offsets:
            if b'\x1b\x68' in pattern:
                patch = (b'\x1b\x68', b'\x01\x23')

            self.patchData(offset, pattern, *patch)

    def patch_AMFIMemcmp(self, offsets):
        for offset, pattern in offsets:
            if b'\xd0\x47' in pattern:
                patch = (b'\xd0\x47', b'\x00\x20')

            self.patchData(offset, pattern, *patch)

    def patch_AppleImage3NORAccess(self, offsets):
        for offset, pattern in offsets:
            if b'\xe0\x47' in pattern:
                patch = (b'\xe0\x47', b'\x00\x20')

            elif b'\x00\x28' in pattern:
                patch = (b'\x00\x28', b'\x00\x20')

            elif b'\xb0\x47' in pattern:
                patch = (b'\xb0\x47', b'\x01\x20')

            self.patchData(offset, pattern, *patch)

    def patch_signatureCheck(self, offsets):
        for offset, pattern in offsets:
            if b'\x08\x46' in pattern:
                patch = (b'\x08\x46', b'\x00\x20')

            self.patchData(offset, pattern, *patch)

    def patchKernel(self):
        offsets = self.findAllOffsets()

        for name in offsets:
            if name == 'cs_enforcement':
                self.patch_CSEnforcement(offsets[name])

            elif name == 'amfi_memcmp':
                self.patch_AMFIMemcmp(offsets[name])

            elif name == 'apple_image3_nor_access':
                self.patch_AppleImage3NORAccess(offsets[name])

            elif name == 'sig_check':
                self.patch_signatureCheck(offsets[name])

        return self.patched_data
