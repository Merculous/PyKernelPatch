
from .find import Find
from .utils import formatBytes, hexStringToHexInt


class Patch(Find):
    def __init__(self, arch, mode, path):
        super().__init__(arch, mode, path)

        self.patched_data = bytearray(self.data)

    def patchData(self, offset, pattern):
        print(f'Patching data at offset: {offset}')

        offset = hexStringToHexInt(offset)

        pattern_len = len(pattern)

        buffer = self.data[offset:offset+pattern_len]

        print(f'{formatBytes(buffer)} -> {formatBytes(pattern)}')

    def patch_debug_enabled(self, offset, pattern):
        pattern[0] = int.from_bytes(b'\x01', 'little')

        self.patchData(offset, pattern)

    def patch_vm_map_enter(self, offset, pattern):
        pattern = pattern.replace(b'\x2e\xd1', b'\x00\x20')

        self.patchData(offset, pattern)

    def patch_amfi_memcmp(self, offset, pattern):
        pattern = pattern.replace(b'\x00\x20', b'\x01\x20')

        self.patchData(offset, pattern)

    def patch_amfi_trust_cache(self, offset, pattern):
        pattern = pattern.replace(b'\xff\x30', b'\x00\x00')

        self.patchData(offset, pattern)

    def patch_nor_signature(self, offset, pattern):
        pattern = b'\x00\x20\x00\x20'

        self.patchData(offset, pattern)

    def patch_nor_llb_1(self, offset, pattern):
        pattern = pattern.replace(b'\x00\x28', b'\x00\x20')

        self.patchData(offset, pattern)

    def patch_nor_llb_2(self, offset, pattern):
        pattern = pattern.replace(b'\x00\x28', b'\x00\x20')

        self.patchData(offset, pattern)

    def patch_nor_llb_3(self, offset, pattern):
        pattern = b'\x01\x20\x01\x20'

        self.patchData(offset, pattern)

    def patch_nor_llb_4(self, offset, pattern):
        pattern = b'\x00\x20\x00\x20'

        self.patchData(offset, pattern)

    def patch(self):
        offsets = self.findAllOffsets()

        for name, (offset, pattern) in offsets.items():
            for func in dir(self):
                if func == f'patch_{name}':
                    func = getattr(self, func)

                    func(offset, bytearray(pattern))

        return self.patched_data
