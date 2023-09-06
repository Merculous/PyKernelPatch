
from .utils import joinPatterns


class Pattern:
    instructions = {
        'ldr': {
            'ldr_r2_r4_x28': b'\xa2\x6a',

            'ldr_r3_r3': b'\x1b\x68',

            'ldr_r4_pc_x214': b'\x85\x4c',

            'ldr_r0_sp_x14': b'\x05\x98',

            'ldr_r4_pc_x20c': b'\x83\x4c',

            'ldr_r6_pc_xac': b'\x2b\x4e',

            'ldr_r1_sp_8': b'\x02\x99',

            'ldr_r1_pc_x14': b'\x05\x49',

            'ldr_r1_r1': b'\x09\x68',

            'ldr_r0_pc_4': b'\x01\x48',

            'ldr_r0_r0': b'\x00\x68',

            'ldr_r3_sp_xc': b'\x03\x9b',

            'ldrb_r4_r0_x11': b'\x44\x7c'

        },
        'mov': {
            'mov_r3_1': b'\x01\x23',

            'mov_r1_r5': b'\x29\x46',

            'mov_r0_r5': b'\x28\x46',

            'mov_r0_r1': b'\x08\x46',

            'mov_sp_r4': b'\xa5\x46',

            'mov_r0_r8': b'\x40\x46',

            'movw_r1_neg1': b'\x4f\xf0\xff\x31',

            'movnew_r8_1': b'\x4f\xf0\x01\x08',

            'movs_r0_0': b'\x00\x20',

            'movs_r1_2': b'\x02\x21',

            'movs_r2_1': b'\x01\x22',

            'movs_r1_1': b'\x01\x21',

            'movs_r2_x13': b'\x13\x22',

            'mov_r0_r4': b'\x20\x46',

            'mov_r2_r11': b'\x5a\x46',

            'movw_r1_x4950': b'\x44\xf6\x50\x11',  # "IP"

            'movs_r3_0': b'\x00\x23',

            'mov_r0_r6': b'\x30\x46'

        },
        'cmp': {
            'cmp_r0_0': b'\x00\x28',

            'cmp_r0_6': b'\x06\x28',

            'cmp_r3_0': b'\x00\x2b'

        },
        'str': {
            'str_r3_sp_8': b'\x02\x93',

            'str_r1_sp_4': b'\x01\x91',

            'str_r1_r0': b'\x01\x60',

            'strw_r8_sp_8': b'\xcd\xf8\x08\x80',

            'strw_r8_sp': b'\xcd\xf8\x00\x80',

            'strw_r8_sp_4': b'\xcd\xf8\x04\x80'
        },
        'and': {
            'andw_r0_r1_6': b'\x01\xf0\x06\x00'
        },
        'pop': {
            'popw_r8_r10_r11': b'\xbd\xe8\x00\x0d',

            'pop_r4_r5_r6_r7_pc': b'\xf0\xbd'
        },
        'add': {
            'add_sp_sp_x14': b'\x05\xb0',

            'adds_r5_x13': b'\x13\x35'
        },
        'it': {
            'it_ne': b'\x18\xbf'
        },
        'sub': {
            'subw_r4_r7_x18': b'\xa7\xf1\x18\x04'
        },
        'b': {
            'b_x23a': b'\x19\xe1',

            'bx_lr': b'\x70\x47',

            'cbz_r0_x12': b'\x38\xb1',

            'blx_r2': b'\x90\x47',

            'bne_x16': b'\x06\xd1',

            'bne_to_movw_r6_x2e2_second': b'\xed\xd1',

            'cbnz_r0_x7c': b'\xc0\xbb',

            'blx_r6': b'\xb0\x47',

            'bne_to_movw_r6_x2e2': b'\xf2\xd1',  # 40 F2 E2 26

            'blx_r4': b'\xa0\x47',

            'blx_r12': b'\xe0\x47',

            'blx_r10': b'\xd0\x47',

            'cbz_r0_x14': b'\x40\xb1'
        }
    }

    # TODO
    # Get rid of useless version requirement.
    # Instead, if a pattern is not found, we will just
    # add more known instructions, and look for a match.
    # Eventually, if we run out of known bytes that could
    # make a match, if there's none, just exit.

    def __init__(self, version):
        self.version = version

    def getHex(self, instruction):
        for base in self.instructions:
            if instruction in self.instructions[base]:
                return self.instructions[base][instruction]

    def form_CSEnforcement(self):
        if self.version in ('5.0', '5.0.1', '5.1', '5.1.1'):
            pattern = (
                self.getHex('ldr_r2_r4_x28'),
                self.getHex('ldr_r3_r3')
            )

        return joinPatterns(pattern)

    def form_AMFIMemcmp(self):
        if self.version == '5.0':
            pattern = (
                self.getHex('blx_r10'),
                self.getHex('movs_r1_1')
            )

        elif self.version == '5.0.1':
            pattern = (
                self.getHex('mov_r1_r5'),
                self.getHex('movs_r2_x13'),
                self.getHex('blx_r10'),
                b'\x01'
            )

        elif self.version == '5.1':
            pattern = (
                self.getHex('mov_r1_r5'),
                self.getHex('movs_r2_x13'),
                self.getHex('blx_r10'),
                self.getHex('movs_r1_1'),
                self.getHex('cbz_r0_x14'),
                self.getHex('adds_r5_x13'),
                b'\x00'
            )

        elif self.version == '5.1.1':
            pattern = (
                self.getHex('mov_r1_r5'),
                self.getHex('movs_r2_x13'),
                self.getHex('blx_r10')
            )

        return joinPatterns(pattern)

    def form_AppleImage3NORAccess(self):
        if self.version in ('5.0', '5.0.1'):
            pattern1 = (
                b'\x00\x80',
                self.getHex('strw_r8_sp_4'),
                self.getHex('str_r3_sp_8'),
                self.getHex('blx_r12'),
                self.getHex('cbnz_r0_x7c')
            )

            pattern2 = (
                self.getHex('blx_r12'),
                self.getHex('cmp_r0_0'),
                self.getHex('it_ne'),
                self.getHex('movnew_r8_1'),
                self.getHex('mov_r0_r8'),
                self.getHex('add_sp_sp_x14')
            )

            pattern3 = (
                self.getHex('movs_r1_2'),
                self.getHex('ldr_r4_pc_x214'),
                self.getHex('blx_r4'),
                self.getHex('cmp_r0_0')
            )

            pattern4 = (
                self.getHex('bne_to_movw_r6_x2e2'),
                self.getHex('ldr_r0_sp_x14'),
                self.getHex('ldr_r4_pc_x20c'),
                self.getHex('blx_r4'),
                self.getHex('cmp_r0_0'),
                self.getHex('bne_to_movw_r6_x2e2_second')
            )

            pattern5 = (
                self.getHex('ldr_r6_pc_xac'),
                self.getHex('mov_r0_r5'),
                self.getHex('ldr_r1_sp_8'),
                self.getHex('blx_r6')
            )

        elif self.version in ('5.1', '5.1.1'):
            if self.version == '5.1':
                pattern1 = (
                    b'\x80',
                    self.getHex('str_r3_sp_8'),
                    self.getHex('blx_r12'),
                    self.getHex('cbnz_r0_x7c'),
                    self.getHex('movw_r1_x4950'),
                    self.getHex('movnew_r8_1'),
                    self.getHex('movs_r3_0')
                )

            else:
                pattern1 = (
                    self.getHex('movs_r2_1'),
                    self.getHex('strw_r8_sp'),
                    self.getHex('strw_r8_sp_4'),
                    self.getHex('str_r3_sp_8'),
                    self.getHex('blx_r12'),
                    b'\xc0'
                )

            if self.version == '5.1':
                pattern2 = (
                    b'\x80',
                    self.getHex('strw_r8_sp_4'),
                    self.getHex('strw_r8_sp_8'),
                    self.getHex('blx_r12'),
                    self.getHex('cmp_r0_0'),
                    self.getHex('it_ne'),
                    b'\x4f\xf0'
                )

            else:
                pattern2 = (
                    b'\x68\xc0',
                    self.getHex('mov_r0_r4'),
                    self.getHex('mov_r2_r11'),
                    self.getHex('ldr_r3_sp_xc'),
                    self.getHex('strw_r8_sp'),
                    self.getHex('strw_r8_sp_4'),
                    self.getHex('strw_r8_sp_8'),
                    self.getHex('blx_r12'),
                    self.getHex('cmp_r0_0'),
                    self.getHex('it_ne'),
                    b'\x4f\xf0'
                )

            pattern3 = (
                self.getHex('movs_r1_2'),
                self.getHex('ldr_r4_pc_x214'),
                self.getHex('blx_r4'),
                self.getHex('cmp_r0_0')
            )

            if self.version == '5.1':
                pattern4 = (
                    self.getHex('cmp_r0_0'),
                    self.getHex('bne_to_movw_r6_x2e2_second'),
                    self.getHex('mov_r0_r6'),
                    self.getHex('ldrb_r4_r0_x11')
                )

            else:
                pattern4 = (
                    self.getHex('bne_to_movw_r6_x2e2'),
                    self.getHex('ldr_r0_sp_x14'),
                    self.getHex('ldr_r4_pc_x20c'),
                    self.getHex('blx_r4'),
                    self.getHex('cmp_r0_0')
                )

            pattern5 = (
                self.getHex('ldr_r6_pc_xac'),
                self.getHex('mov_r0_r5'),
                self.getHex('ldr_r1_sp_8'),
                self.getHex('blx_r6')
            )

        return joinPatterns(
            pattern1,
            pattern2,
            pattern3,
            pattern4,
            pattern5,
        )

    def form_signatureCheck(self):
        if self.version in ('5.0', '5.0.1'):
            pattern = (
                self.getHex('movw_r1_neg1'),
                self.getHex('subw_r4_r7_x18'),
                self.getHex('mov_r0_r1'),
                self.getHex('mov_sp_r4'),
                self.getHex('popw_r8_r10_r11'),
                b'\xf0'
            )

        elif self.version == '5.1':
            pattern = (
                b'\xff\x31',
                self.getHex('subw_r4_r7_x18'),
                self.getHex('mov_r0_r1'),
                self.getHex('mov_sp_r4'),
                self.getHex('popw_r8_r10_r11'),
                self.getHex('pop_r4_r5_r6_r7_pc')
            )

        elif self.version == '5.1.1':
            pattern = (
                self.getHex('subw_r4_r7_x18'),
                self.getHex('mov_r0_r1'),
                self.getHex('mov_sp_r4'),
                b'\xbd\xe8'
            )

        return joinPatterns(pattern)
