
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

            elif b'\x12\x68' in pattern:
                patch = (b'\x12\x68', b'\x01\x22')

            self.patchData(offset, pattern, *patch)

    def patch_vm_map_enter(self, offsets):
        for offset, pattern in offsets:
            if b'\x06\x28' in pattern:
                patch = (b'\x06\x28', b'\xff\x28')

            self.patchData(offset, pattern, *patch)

    def patch_tfp0(self, offsets):
        for offset, pattern in offsets:
            if b'\x06\xd1' in pattern:
                patch = (b'\x06\xd1', b'\x06\xe0')

            self.patchData(offset, pattern, *patch)

    def patch_AMFICertification(self, offsets):
        for offset, pattern in offsets:
            if b'\x91\x42' in pattern:
                patch = (b'\x91\x42', b'\x11\x46')

            self.patchData(offset, pattern, *patch)

    def patch_Sandbox(self, offsets):
        for offset, pattern in offsets:
            if b'\x06\xf0\x7b\xfa' in pattern:
                patch = (b'\x06\xf0\x7b\xfa', b'\x00\x20\x00\x20')

            self.patchData(offset, pattern, *patch)

    def patch_SandboxEntitlement(self, offsets):
        for offset, pattern in offsets:
            if b'security' in pattern:
                patch = (b'security', b's3curity')

            self.patchData(offset, pattern, *patch)

    def patch_AMFIMemcmp(self, offsets):
        for offset, pattern in offsets:
            if b'\xd0\x47' in pattern:
                patch = (b'\xd0\x47', b'\x00\x20')

            self.patchData(offset, pattern, *patch)

    def patch_AppleImage3NORAccess(self, offsets):
        version = self.pattern_obj.version

        for offset, pattern in offsets:
            if version in ('5.0', '5.0.1', '5.1', '5.1.1'):
                if b'\xe0\x47' in pattern:
                    patch = (b'\xe0\x47', b'\x00\x20')

                elif b'\x00\x28' in pattern:
                    patch = (b'\x00\x28', b'\x00\x20')

                elif b'\xb0\x47' in pattern:
                    patch = (b'\xb0\x47', b'\x01\x20')

            elif version in ('6.0', '6.1.3'):
                if b'\x40\xf0\x0e\x81' in pattern:
                    patch = (b'\x40\xf0\x0e\x81', b'\x00\x20\x00\x20')

                # The patch below requires b'\x00\x28' in the pattern.
                # My function cannot work without it, so I need to have
                # the version requirement as the b'\x00\x28' will be used
                # instead of the one below, which is wrong.

                elif b'\x40\xf0\x04\x81' in pattern:
                    patch = (b'\x40\xf0\x04\x81', b'\x00\x20\x00\x20')

            self.patchData(offset, pattern, *patch)

    def patch_signatureCheck(self, offsets):
        for offset, pattern in offsets:
            if b'\x08\x46' in pattern:
                patch = (b'\x08\x46', b'\x00\x20')

            self.patchData(offset, pattern, *patch)

    def patchKernel(self):
        offsets = self.findAllOffsets()

        for name in offsets:
            if offsets[name]:
                if name == 'cs_enforcement':
                    self.patch_CSEnforcement(offsets[name])

                elif name == 'vm_map_enter':
                    self.patch_vm_map_enter(offsets[name])

                elif name == 'tfp0':
                    self.patch_tfp0(offsets[name])

                elif name == 'amfi_certification':
                    self.patch_AMFICertification(offsets[name])

                elif name == 'sandbox':
                    self.patch_Sandbox(offsets[name])

                elif name == 'sandbox_entitlement':
                    self.patch_SandboxEntitlement(offsets[name])

                elif name == 'amfi_memcmp':
                    self.patch_AMFIMemcmp(offsets[name])

                elif name == 'apple_image3_nor_access':
                    self.patch_AppleImage3NORAccess(offsets[name])

                elif name == 'sig_check':
                    self.patch_signatureCheck(offsets[name])

        return self.patched_data
