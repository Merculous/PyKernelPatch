
from .find import Find

from binpatch.patch import patchBufferAtIndex


class Patch(Find):
    def __init__(self, arch, mode, path):
        super().__init__(arch, mode, path)

        self.patched_data = bytearray(self.data)

    def patchData(self, offset, old, new):
        print(f'Patching data at offset: {offset}')

        patchBufferAtIndex(self.patched_data, offset, old, new)

    def patchPattern(self, pattern, old, new):
        pattern = pattern.replace(old, new)
        return pattern

    def patch_debug_enabled(self, offset, pattern):
        if self.version == '4.3.3':
            patched = self.patchPattern(pattern, b'\x00\x00\x00\x00\x01', b'\x01\x00\x00\x00\x01')

        elif self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            patched = self.patchPattern(pattern, b'\x1b\x68', b'\x01\x23')

        self.patchData(offset, pattern, patched)

    def patch_vm_map_enter(self, offset, pattern):
        if self.version == '4.3.3':
            patched = self.patchPattern(pattern, b'\x2e\xd1', b'\x00\x20')

        elif self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            pass

        self.patchData(offset, pattern, patched)

    def patch_amfi_memcmp(self, offset, pattern):
        if self.version == '4.3.3':
            patched = self.patchPattern(pattern, b'\x00\x20', b'\x01\x20')

        elif self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            patched = self.patchPattern(pattern, b'\xd0\x47', b'\x00\x20')

        self.patchData(offset, pattern, patched)

    def patch_amfi_trust_cache(self, offset, pattern):
        if self.version == '4.3.3':
            patched = self.patchPattern(pattern, b'\xff\x30', b'\x00\x00')

        elif self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            pass

        self.patchData(offset, pattern, patched)

    def patch_nor_signature(self, offset, pattern):
        if self.version == '4.3.3':
            patched = self.patchPattern(pattern, b'\xff\xf7\x25\xff', b'\x00\x20\x00\x20',)

        elif self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            patched = self.patchPattern(pattern, b'\x08\x46', b'\x00\x20')

        self.patchData(offset, pattern, patched)

    def patch_nor_llb_1(self, offset, pattern):
        if self.version == '4.3.3':
            patched = self.patchPattern(pattern, b'\xff\xf7\x0c\xff', b'\x00\x20\x00\x20')

        elif self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            patched = self.patchPattern(pattern, b'\xe0\x47', b'\x00\x20')

        self.patchData(offset, pattern, patched)

    def patch_nor_llb_2(self, offset, pattern):
        if self.version == '4.3.3':
            patched = self.patchPattern(pattern, b'\x00\x28', b'\x00\x20')

        elif self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            patched = self.patchPattern(pattern, b'\xe0\x47', b'\x00\x20')

        self.patchData(offset, pattern, patched)

    def patch_nor_llb_3(self, offset, pattern):
        if self.version == '4.3.3':
            patched = self.patchPattern(pattern, b'\x00\x28', b'\x00\x20')

        elif self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            patched = self.patchPattern(pattern, b'\x00\x28', b'\x00\x20')

        self.patchData(offset, pattern, patched)

    def patch_nor_llb_4(self, offset, pattern):
        if self.version == '4.3.3':
            patched = self.patchPattern(pattern, b'\xff\xf7\x50\xfc', b'\x01\x20\x01\x20')

        elif self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            patched = self.patchPattern(pattern, b'\x00\x28', b'\x00\x20')

        self.patchData(offset, pattern, patched)

    def patch_nor_llb_5(self, offset, pattern):
        if self.version == '4.3.3':
            patched = self.patchPattern(pattern, b'\x4f\xf0\xff\x30', b'\x00\x20\x00\x20')

        elif self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            patched = self.patchPattern(pattern, b'\xb0\x47', b'\x01\x20')

        self.patchData(offset, pattern, patched)

    def patch(self):
        offsets = self.findAllOffsets()

        for name in offsets:
            if offsets[name]:
                offset, pattern = offsets[name]

                for func in dir(self):
                    if func == f'patch_{name}':
                        print(f'[#] {name}')

                        func = getattr(self, func)

                        func(offset, bytearray(pattern))

        return self.patched_data
