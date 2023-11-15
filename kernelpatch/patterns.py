
from .instructions import Instructions


class Pattern(Instructions):
    def __init__(self, arch, mode):
        super().__init__(arch, mode)

    def convertBytesToInstruction(self, value, offset=0):
        instruction = self.hexToInstruction(value, offset)
        return f'{instruction["mnemonic"]} {instruction["op_str"]}'

    def form_vm_map_enter(self):
        if self.version in ('3.1.3'):
            pattern = (
                b'\x40\xf0\x36\x80',
                b'\x63\x08'
            )

        elif self.version in ('4.0', '4.0.1', '4.0.2', '4.1'):
            pattern = (
                b'\x16\xf0\x02\x0f',
                b'\x30\xd1'
            )

        elif self.version in ('4.3', '4.3.1', '4.3.2', '4.3.3'):
            pattern = (
                b'\x18\xf0\x02\x0f',
                b'\x2e\xd1'
            )

        elif self.version in ('6.0', '6.0.1', '6.1', '6.1.2', '6.1.3', '6.1.6'):
            pattern = (
                b'\x06\x28',
                b'\x01\xd0'
            )

        return pattern

    def form_tfp0(self):
        if self.version in ('6.0', '6.0.1', '6.1', '6.1.2', '6.1.3', '6.1.6'):
            pattern = (
                b'\x01\x91',
                b'\x06\xd1',
                b'\x02\xa8'
            )

        return pattern

    def form_debug_enabled(self):
        # NOTE This is actually _cs_enforcement_disable

        if self.version in ('3.1.3', '4.0', '4.0.1', '4.0.2', '4.1', '4.2.1', '4.3', '4.3.1', '4.3.2', '4.3.3'):
            pattern = (
                b'\x00\x00\x00\x00',  # This is the value
                b'\x01\x00\x00\x00',
                b'\x80\x00\x00\x00',
                b'\x00\x00\x00\x00'
            )

        elif self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            pattern = (
                b'\x1b\x68',
                b'\x00\x2b'
            )

        elif self.version in ('6.1.3', '6.1.6'):
            pattern = (
                b'\x12\x68',
                b'\x00\x2a'
            )

        return pattern

    def form_amfi_trust_cache(self):
        if self.version in ('4.0', '4.0.1', '4.0.2', '4.1', '4.2.1', '4.3', '4.3.1', '4.3.2', '4.3.3'):
            pattern = (
                b'\x4f\xf0\xff\x30',
                b'\x2c\xe0'
            )

        elif self.version in ('6.1.3', '6.1.6'):
            pattern = (
                b'\xce\x9a',
                b'\x91\x42',
                b'\x02\xbf'
            )

        return pattern

    def form_sandbox_mac_label_get(self):
        if self.version in ('6.1.3', '6.1.6'):
            pattern = (
                b'\x06\xf0\x7b\xfa',
                b'\x04\x46'
            )

        return pattern

    def form_sandbox_entitlement_container_required(self):
        # The "e" in security changes to a "3"
        if self.version in ('6.1.3', '6.1.6'):
            pattern = (
                b'com.apple.private.security.container-required',
            )

        return pattern

    def form_amfi_memcmp(self):
        if self.version in ('3.1.3', '4.0', '4.0.1', '4.0.2', '4.1', '4.2.1'):
            pattern = (
                b'\x00\xb1',
                b'\x00\x24',
                b'\x20\x46'
            )

        elif self.version in ('4.3', '4.3.1', '4.3.2', '4.3.3'):
            pattern = (
                b'\xb4\x42',
                b'\xea\xd1',
                b'\x00\x20'
            )

        elif self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            pattern = (
                b'\xd0\x47',
                b'\x01\x21'
            )

        return pattern

    def form_nor_signature(self):
        if self.version in ('3.1.3'):
            pattern = (
                b'\xff\xf7\x29\xff',
                b'\xf8\xb1'
            )

        elif self.version in ('4.0', '4.0.1', '4.0.2', '4.1', '4.2.1', '4.3', '4.3.1', '4.3.2', '4.3.3'):
            pattern = (
                b'\xff\xf7\x25\xff',
                b'\xf8\xb1'
            )

        elif self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            pattern = (
                b'\x4f\xf0\xff\x31',
                b'\xa7\xf1\x18\x04',
                b'\x08\x46',
                b'\xa5\x46'
            )

        return pattern

    def form_nor_llb_1(self):
        if self.version in ('3.1.3'):
            pattern = (
                b'\xff\xf7\x10\xff',
                b'\x00\x38'
            )

        elif self.version in ('4.0', '4.0.1', '4.0.2', '4.1', '4.2.1', '4.3', '4.3.1', '4.3.2', '4.3.3'):
            pattern = (
                b'\xff\xf7\x0c\xff',
                b'\x00\x38'
            )

        elif self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            pattern = (
                b'\xdf\xf8\xc4\xc0',
                b'\x20\x46',
                b'\x01\x22',
                b'\xcd\xf8\x00\x80',
                b'\xcd\xf8\x04\x80',
                b'\x02\x93',
                b'\xe0\x47'
            )

        elif self.version in ('6.0', '6.0.1', '6.1', '6.1.2', '6.1.3', '6.1.6'):
            pattern = (
                b'\x40\xf0\x0e\x81',
                b'\x04\x98',
                b'\x00\xf0\x6c\xfa'
            )

        return pattern

    def form_nor_llb_2(self):
        # SHSH

        if self.version in ('3.1.3'):
            pattern = (
                b'\x68\x4b',
                b'\x98\x47',
                b'\x00\x28'
            )

        elif self.version in ('4.0', '4.0.1', '4.0.2', '4.1', '4.2.1', '4.3', '4.3.1', '4.3.2', '4.3.3'):
            pattern = (
                b'\x02\x21',
                b'\x7c\x4b',
                b'\x98\x47',
                b'\x00\x28'
            )

        elif self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            pattern = (
                b'\xe0\x47',
                b'\x00\x28',
                b'\x18\xbf',
                b'\x4f\xf0\x01\x08',
                b'\x40\x46'
            )

        elif self.version in ('6.0', '6.0.1', '6.1', '6.1.2', '6.1.3', '6.1.6'):
            pattern = (
                b'\x40\xf0\x04\x81',
                b'\x31\x46',
                b'\x40\xf2\xe2\x24'
            )

        return pattern

    def form_nor_llb_3(self):
        # CERT

        if self.version in ('3.1.3'):
            pattern = (
                b'\xff\xf7\xd1\xfd',
                b'\x04\x46'
            )

        elif self.version in ('4.0', '4.0.1', '4.0.2', '4.1', '4.2.1', '4.3', '4.3.1', '4.3.2', '4.3.3'):
            pattern = (
                b'\xff\xf7\xab\xfd',
                b'\x04\x46',
                b'\x00\x28'
            )

        elif self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            pattern = (
                b'\x85\x4c'
                b'\xa0\x47',
                b'\x00\x28'
            )

        return pattern

    def form_nor_llb_4(self):
        if self.version in ('3.1.3'):
            pattern = (
                b'\xff\xf7\xae\xfc',
                b'\x00\xb3'
            )

        elif self.version in ('4.0', '4.0.1', '4.0.2', '4.1', '4.2.1', '4.3', '4.3.1', '4.3.2', '4.3.3'):
            pattern = (
                b'\xff\xf7\x50\xfc',
                b'\x00\xb3'
            )

        elif self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            pattern = (
                b'\x83\x4c',
                b'\xa0\x47',
                b'\x00\x28',
                b'\xed\xd1'
            )

        return pattern

    def form_nor_llb_5(self):
        if self.version in ('3.1.3', '4.0', '4.0.1', '4.0.2', '4.1', '4.2.1', '4.3', '4.3.1', '4.3.2', '4.3.3'):
            pattern = (
                b'\x4f\xf0\xff\x30',
                b'\x2d\xe0'
            )

        elif self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            pattern = (
                b'\x02\x99',
                b'\xb0\x47',
                b'\x00\x28'
            )

        return pattern

    def form_sandbox_profile(self):
        if self.version in ('4.3', '4.3.1'):
            pattern = (
                b'\x1b\x68',
                b'\x13\xf0\x04\x0f',
                b'\x04\xd0'
            )

        return pattern

    def form_seatbelt_profile(self):
        if self.version == '4.0':
            pattern = (
                b'seatbelt-profile',
            )

        return pattern
