
from .instructions import Instructions


class Pattern(Instructions):
    def __init__(self, arch, mode):
        super().__init__(arch, mode)

    def convertBytesToInstruction(self, value, offset=0):
        instruction = self.hexToInstruction(value, offset)
        return f'{instruction["mnemonic"]} {instruction["op_str"]}'

    def form_vm_map_enter(self):
        pattern = (
            b'\x18\xf0\x02\x0f',
            b'\x2e\xd1'
        )

        return pattern

    def form_debug_enabled(self):
        pattern = (
            b'\x00\x00\x00\x00',  # This is the value
            b'\x01\x00\x00\x00',
            b'\x80\x00\x00\x00',
            b'\x00\x00\x00\x00'
        )

        return pattern

    def form_amfi_trust_cache(self):
        pattern = (
            b'\x4f\xf0\xff\x30',
            b'\x2c\xe0'
        )

        return pattern

    def form_amfi_memcmp(self):
        pattern = (
            b'\xb4\x42',
            b'\xea\xd1',
            b'\x00\x20'
        )

        return pattern

    def form_nor_signature(self):
        pattern = (
            b'\xff\xf7\x25\xff',
            b'\xf8\xb1'
        )

        return pattern

    def form_nor_llb_1(self):
        pattern = (
            b'\xff\xf7\x0c\xff',
            b'\x00\x38'
        )

        return pattern

    def form_nor_llb_2(self):
        pattern = (
            b'\x02\x21',
            b'\x7c\x4b',
            b'\x98\x47',
            b'\x00\x28'
        )

        return pattern

    def form_nor_llb_3(self):
        pattern = (
            b'\xff\xf7\xab\xfd',
            b'\x04\x46',
            b'\x00\x28'
        )

        return pattern

    def form_nor_llb_4(self):
        pattern = (
            b'\xff\xf7\x50\xfc',
            b'\x00\xb3'
        )

        return pattern

    def form_nor_llb_5(self):
        pattern = (
            b'\x4f\xf0\xff\x30',
            b'\x2d\xe0'
        )

        return pattern
