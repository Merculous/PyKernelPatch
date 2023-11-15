
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
        if self.version in ('3.1.3', '4.0', '4.0.1', '4.0.2', '4.1', '4.2.1', '4.3', '4.3.1', '4.3.2', '4.3.3'):
            patched = self.patchPattern(
                pattern, b'\x00\x00\x00\x00\x01', b'\x01\x00\x00\x00\x01')

        elif self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            patched = self.patchPattern(pattern, b'\x1b\x68', b'\x01\x23')

        elif self.version in ('6.1.3', '6.1.6'):
            patched = self.patchPattern(pattern, b'\x12\x68', b'\x01\x22')

        self.patchData(offset, pattern, patched)

    def patch_vm_map_enter(self, offset, pattern):
        if self.version in ('3.1.3'):
            patched = self.patchPattern(
                pattern, b'\x40\xf0\x36\x80', b'\x8b\x46\x8b\x46')

        elif self.version in ('4.1'):
            patched = self.patchPattern(pattern, b'\x30\xd1', b'\x00\x20')

        elif self.version in ('4.3', '4.3.1', '4.3.2', '4.3.3'):
            patched = self.patchPattern(pattern, b'\x2e\xd1', b'\x00\x20')

        elif self.version in ('6.0', '6.0.1', '6.1', '6.1.2', '6.1.3', '6.1.6'):
            patched = self.patchPattern(pattern, b'\x06\x28', b'\xff\x28')

        self.patchData(offset, pattern, patched)

    def patch_tfp0(self, offset, pattern):
        if self.version in ('6.0', '6.0.1', '6.1', '6.1.2', '6.1.3', '6.1.6'):
            patched = self.patchPattern(pattern, b'\x06\xd1', b'\x06\xe0')

        self.patchData(offset, pattern, patched)

    def patch_amfi_memcmp(self, offset, pattern):
        if self.version in ('3.1.3', '4.0', '4.0.1', '4.0.2', '4.1', '4.2.1'):
            patched = self.patchPattern(pattern, b'\x00\x24', b'\x01\x24')

        elif self.version in ('4.3', '4.3.1', '4.3.2', '4.3.3'):
            patched = self.patchPattern(pattern, b'\x00\x20', b'\x01\x20')

        elif self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            patched = self.patchPattern(pattern, b'\xd0\x47', b'\x00\x20')

        self.patchData(offset, pattern, patched)

    def patch_amfi_trust_cache(self, offset, pattern):
        if self.version in ('4.0', '4.0.1', '4.0.2', '4.1', '4.2.1', '4.3', '4.3.1', '4.3.2', '4.3.3'):
            patched = self.patchPattern(pattern, b'\xff\x30', b'\x00\x00')

        elif self.version in ('6.1.3', '6.1.6'):
            patched = self.patchPattern(pattern, b'\x91\x42', b'\x11\x46')

        self.patchData(offset, pattern, patched)

    def patch_sandbox_mac_label_get(self, offset, pattern):
        if self.version in ('6.1.3', '6.1.6'):
            patched = self.patchPattern(
                pattern, b'\x06\xf0\x7b\xfa', b'\x00\x20\x00\x20')

        self.patchData(offset, pattern, patched)

    def patch_sandbox_entitlement_container_required(self, offset, pattern):
        if self.version in ('6.1.3', '6.1.6'):
            patched = self.patchPattern(pattern, b'security', b's3curity')

        self.patchData(offset, pattern, patched)

    def patch_nor_signature(self, offset, pattern):
        if self.version in ('3.1.3'):
            patched = self.patchPattern(
                pattern, b'\xff\xf7\x29\xff', b'\x00\x20\x00\x20',)

        elif self.version in ('4.0', '4.0.1', '4.0.2', '4.1', '4.2.1', '4.3', '4.3.1', '4.3.2', '4.3.3'):
            patched = self.patchPattern(
                pattern, b'\xff\xf7\x25\xff', b'\x00\x20\x00\x20',)

        elif self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            patched = self.patchPattern(pattern, b'\x08\x46', b'\x00\x20')

        self.patchData(offset, pattern, patched)

    def patch_nor_llb_1(self, offset, pattern):
        if self.version in ('3.1.3'):
            patched = self.patchPattern(
                pattern, b'\xff\xf7\x10\xff', b'\x00\x20\x00\x20')

        elif self.version in ('4.0', '4.0.1', '4.0.2', '4.1', '4.2.1', '4.3', '4.3.1', '4.3.2', '4.3.3'):
            patched = self.patchPattern(
                pattern, b'\xff\xf7\x0c\xff', b'\x00\x20\x00\x20')

        elif self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            patched = self.patchPattern(pattern, b'\xe0\x47', b'\x00\x20')

        elif self.version in ('6.0', '6.0.1', '6.1', '6.1.2', '6.1.3', '6.1.6'):
            patched = self.patchPattern(
                pattern, b'\x40\xf0\x0e\x81', b'\x00\x20\x00\x20')

        self.patchData(offset, pattern, patched)

    def patch_nor_llb_2(self, offset, pattern):
        if self.version in ('3.1.3'):
            patched = self.patchPattern(pattern, b'\x98\x47', b'\x00\x20')

        elif self.version in ('4.0', '4.0.1', '4.0.2', '4.1', '4.2.1', '4.3', '4.3.1', '4.3.2', '4.3.3'):
            patched = self.patchPattern(pattern, b'\x00\x28', b'\x00\x20')

        elif self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            patched = self.patchPattern(pattern, b'\xe0\x47', b'\x00\x20')

        elif self.version in ('6.0', '6.0.1', '6.1', '6.1.2', '6.1.3', '6.1.6'):
            patched = self.patchPattern(
                pattern, b'\x40\xf0\x04\x81', b'\x00\x20\x00\x20')

        self.patchData(offset, pattern, patched)

    def patch_nor_llb_3(self, offset, pattern):
        # NOTE 3.1.3 patches call to something with img3
        # Now I'm not 100% this is needed since I could just
        # patch the CMP, but I will have to test that...

        if self.version in ('3.1.3'):
            patched = self.patchPattern(
                pattern, b'\xff\xf7\xd1\xfd', b'\x00\x20\x00\x20')

        elif self.version in ('4.0', '4.0.1', '4.0.2', '4.1', '4.2.1', '4.3', '4.3.1', '4.3.2', '4.3.3'):
            patched = self.patchPattern(pattern, b'\x00\x28', b'\x00\x20')

        elif self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            patched = self.patchPattern(pattern, b'\x00\x28', b'\x00\x20')

        self.patchData(offset, pattern, patched)

    def patch_nor_llb_4(self, offset, pattern):
        if self.version in ('3.1.3'):
            patched = self.patchPattern(
                pattern, b'\xff\xf7\xae\xfc', b'\x01\x20\x01\x20')

        elif self.version in ('4.0', '4.0.1', '4.0.2', '4.1', '4.2.1', '4.3', '4.3.1', '4.3.2', '4.3.3'):
            patched = self.patchPattern(
                pattern, b'\xff\xf7\x50\xfc', b'\x01\x20\x01\x20')

        elif self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            patched = self.patchPattern(pattern, b'\x00\x28', b'\x00\x20')

        self.patchData(offset, pattern, patched)

    def patch_nor_llb_5(self, offset, pattern):
        if self.version in ('3.1.3', '4.0', '4.0.1', '4.0.2', '4.1', '4.2.1', '4.3', '4.3.1', '4.3.2', '4.3.3'):
            patched = self.patchPattern(
                pattern, b'\x4f\xf0\xff\x30', b'\x00\x20\x00\x20')

        elif self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            patched = self.patchPattern(pattern, b'\xb0\x47', b'\x01\x20')

        self.patchData(offset, pattern, patched)

    def patch_sandbox_profile(self, offset, pattern):
        if self.version in ('4.3', '4.3.1'):
            patched = self.patchPattern(
                pattern, b'\x1b\x68\x13\xf0\x04\x0f', b'\x06\x9b\x0b\xb1\x00\x23')

        self.patchData(offset, pattern, patched)

    def patch_seatbelt_profile(self, offset, pattern):
        if self.version == '4.0':
            patched = self.patchPattern(pattern, b'seatbelt', b'xih8sn0w')

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
