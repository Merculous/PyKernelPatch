
from .find import Find
from .utils import hexOffsetToHexInt


class Patch(Find):
    def __init__(self, data):
        super().__init__(data)

        self.patched_data = bytearray(self.data[:])

    def patchOffset(self, old, new, offset):
        i = hexOffsetToHexInt(offset)

        pattern_len = len(old)

        buffer = self.patched_data[i:i+pattern_len]

        if old in buffer:
            new_buffer = buffer.replace(old, new)
            self.patched_data[i:i+pattern_len] = new_buffer

    def patch_CSEnforcement(self, offset, pattern):
        new_pattern = pattern.replace(b'\x1b\x68', b'\x01\x23')
        self.patchOffset(pattern, new_pattern, offset)

    def patch_Vm_map_enter(self, offset, pattern):
        new_pattern = pattern.replace(b'\x06\x28', b'\xff\x28')
        self.patchOffset(pattern, new_pattern, offset)

    def patch_Tfp0(self, offset, pattern):
        new_pattern = pattern.replace(b'\x06\xd1', b'\x06\xe0')
        self.patchOffset(pattern, new_pattern, offset)

    def patch_PE_i_can_has_debugger(self, offset, pattern):
        if b'\x38\xb1\x05\x49' in pattern:
            new_pattern = pattern.replace(b'\x38\xb1\x05\x49', b'\x01\x20\x70\x47')
            self.patchOffset(pattern, new_pattern, offset)

        elif b'\x00\x68' in pattern:
            new_pattern = pattern.replace(b'\x00\x68', b'\x01\x20')
            self.patchOffset(pattern, new_pattern, offset)

    def patch_AMFIHook(self, offset, pattern):
        new_pattern = pattern.replace(b'\x90\x47', b'\xc0\x46')
        self.patchOffset(pattern, new_pattern, offset)

    def patch_AMFIMemcmp(self, offset, pattern):
        new_pattern = pattern.replace(b'\xd0\x47', b'\x00\x20')
        self.patchOffset(pattern, new_pattern, offset)

    def patch_AppleImage3NORAccess(self, offset, pattern):
        if b'\xe0\x47' in pattern:
            new_pattern = pattern.replace(b'\xe0\x47', b'\x00\x20')

        elif b'\x00\x28' in pattern:
            new_pattern = pattern.replace(b'\x00\x28', b'\x00\x20')

        elif b'\xb0\x47' in pattern:
            new_pattern = pattern.replace(b'\xb0\x47', b'\x01\x20')

        self.patchOffset(pattern, new_pattern, offset)

    def patch_SignatureCheck(self, offset, pattern):
        new_pattern = pattern.replace(b'\x08\x46', b'\x00\x20')
        self.patchOffset(pattern, new_pattern, offset)

    def patchKernel(self):
        for offset in self.findOffsets():
            offset, name, pattern = offset

            if name == 'cs_enforcement':
                self.patch_CSEnforcement(offset, pattern)

            elif name == 'vm_map_enter':
                self.patch_Vm_map_enter(offset, pattern)

            elif name == 'tfp0':
                self.patch_Tfp0(offset, pattern)

            elif name == 'pe_i_can_has_debugger':
                self.patch_PE_i_can_has_debugger(offset, pattern)

            elif name == 'amfi_hook':
                self.patch_AMFIHook(offset, pattern)

            elif name == 'amfi_memcmp':
                self.patch_AMFIMemcmp(offset, pattern)

            elif name == 'apple_image3_nor_access':
                self.patch_AppleImage3NORAccess(offset, pattern)

            elif name == 'sig_check':
                self.patch_SignatureCheck(offset, pattern)

        return self.patched_data
