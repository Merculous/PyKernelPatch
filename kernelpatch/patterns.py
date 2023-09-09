
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

            'ldrb_r4_r0_x11': b'\x44\x7c',

            'ldr_r2_r2': b'\x12\x68',

            'ldr_r2_sp_x338': b'\xce\x9a',

            'ldr_r4_pc_x40': b'\x10\x4c',

            'ldr_r1_r4_8': b'\xa1\x68',

            'ldr_r0_sp_x10': b'\x04\x98',

            'ldrb_r0_r1_x10_!': b'\x11\xf8\x10\x0f',

            'ldrb_r2_r6_x11': b'\x72\x7c',

            'ldrb_r3_r1_3': b'\xcb\x78',

            'ldrb_r1_r1_2': b'\x89\x78'

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

            'mov_r0_r6': b'\x30\x46',

            'mov_r4_r0': b'\x04\x46',

            'movw_r4_x2e2': b'\x40\xf2\xe2\x24',

            'movt_r4_xe000': b'\xce\xf2\x00\x04',

            'mov_r1_r6': b'\x31\x46'

        },
        'cmp': {
            'cmp_r0_0': b'\x00\x28',

            'cmp_r0_6': b'\x06\x28',

            'cmp_r3_0': b'\x00\x2b',

            'cmp_r2_0': b'\x00\x2a',

            'cmp_r1_r2': b'\x91\x42'

        },
        'str': {
            'str_r3_sp_8': b'\x02\x93',

            'str_r1_sp_4': b'\x01\x91',

            'str_r1_r0': b'\x01\x60',

            'strw_r8_sp_8': b'\xcd\xf8\x08\x80',

            'strw_r8_sp': b'\xcd\xf8\x00\x80',

            'strw_r8_sp_4': b'\xcd\xf8\x04\x80',

            'str_r1_sp_x64': b'\x19\x91'

        },
        'and': {
            'andw_r0_r1_6': b'\x01\xf0\x06\x00',

            'and_r0_r0_6': b'\x00\xf0\x06\x00'

        },
        'pop': {
            'popw_r8_r10_r11': b'\xbd\xe8\x00\x0d',

            'pop_r4_r5_r6_r7_pc': b'\xf0\xbd'
        },
        'add': {
            'add_sp_sp_x14': b'\x05\xb0',

            'adds_r5_x13': b'\x13\x35',

            'addeqw_sp_sp_x33c': b'\x0d\xf5\x4f\x7d',

            'add_r4_pc': b'\x7c\x44',

            'addw_r0_r4_x20': b'\x04\xf1\x20\x00',

            'addw_r0_r4_x6c': b'\x04\xf1\x6c\x00'

        },
        'it': {
            'it_ne': b'\x18\xbf',

            'itt_eq': b'\x04\xbf',

            'ittt_eq': b'\x02\xbf'
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

            'cbz_r0_x14': b'\x40\xb1',

            'beq_8': b'\x01\xd0',

            'b_x2a': b'\x10\xe0',

            'bl_x64da': b'\x06\xf0\x67\xfa',

            'bl_x650a': b'\x06\xf0\x7b\xfa',

            'cbz_r4_x34': b'\x6c\xb1',

            'bnew_x220': b'\x40\xf0\x0e\x81',

            'bl_x4e2': b'\x00\xf0\x6c\xfa',

            'bnew_x212': b'\x40\xf0\x04\x81',

            'bl_xdc0': b'\x00\xf0\xde\xfe'

        },
        'or': {
            'eoreq_r6_r0_1': b'\x80\xf0\x01\x06'
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

        elif self.version == '6.1.3':
            pattern = (
                self.getHex('ldr_r2_r2'),
                self.getHex('cmp_r2_0'),
                self.getHex('itt_eq'),
                self.getHex('eoreq_r6_r0_1')
            )

        return joinPatterns(pattern)

    def form_vm_map_enter(self):
        if self.version == '6.0':
            pattern = (
                self.getHex('and_r0_r0_6'),
                self.getHex('cmp_r0_6'),
                self.getHex('beq_8'),
                self.getHex('str_r1_sp_x64'),
                self.getHex('b_x2a'),
            )

        elif self.version == '6.1.3':
            pattern = (
                self.getHex('cmp_r0_6'),
                self.getHex('beq_8'),
                self.getHex('str_r1_sp_x64'),
                self.getHex('b_x2a')
            )

        return joinPatterns(pattern)

    def form_tfp0(self):
        if self.version in ('6.0', '6.1.3'):
            pattern = (
                self.getHex('str_r1_sp_4'),
                self.getHex('bne_x16')
            )

        return joinPatterns(pattern)

    def form_AMFICertification(self):
        if self.version == '6.1.3':
            pattern = (
                self.getHex('ldr_r2_sp_x338'),
                self.getHex('cmp_r1_r2'),
                self.getHex('ittt_eq'),
                self.getHex('addeqw_sp_sp_x33c'),
                b'\xbd\xe8'
            )

        return joinPatterns(pattern)

    def form_Sandbox(self):
        if self.version == '6.1.3':
            pattern = (
                self.getHex('ldr_r4_pc_x40'),
                self.getHex('add_r4_pc'),
                self.getHex('addw_r0_r4_x20'),
                self.getHex('bl_x64da'),
                self.getHex('ldr_r1_r4_8'),
                self.getHex('mov_r0_r5'),
                self.getHex('bl_x650a'),
                self.getHex('mov_r4_r0'),
                self.getHex('cbz_r4_x34'),
                self.getHex('addw_r0_r4_x6c'),
                self.getHex('movs_r1_1')
            )

        return joinPatterns(pattern)

    def form_SandboxEntitlement(self):
        if self.version == '6.1.3':
            # com.apple.private.security.container-required
            pattern = (
                b'\x76',
                b'\x61',
                b'\x74',
                b'\x65',
                b'\x2e',
                b'\x73',
                b'\x65',
                b'\x63',
                b'\x75',
                b'\x72',
                b'\x69',
                b'\x74',
                b'\x79',
                b'\x2e',
                b'\x63',
                b'\x6f',
                b'\x6e',
                b'\x74',
                b'\x61'
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

            return joinPatterns(
                pattern1,
                pattern2,
                pattern3,
                pattern4,
                pattern5,
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

        if self.version == '6.0':
            pattern1 = (
                self.getHex('ldr_r0_sp_x10'),
                self.getHex('movs_r1_2'),
                self.getHex('bl_xdc0'),
                self.getHex('movw_r4_x2e2'),
                self.getHex('cmp_r0_0'),
                self.getHex('movt_r4_xe000'),
                self.getHex('bnew_x220'),
                self.getHex('ldr_r0_sp_x10'),
                self.getHex('bl_x4e2'),
                self.getHex('movw_r4_x2e2'),
                self.getHex('cmp_r0_0'),
                self.getHex('movt_r4_xe000'),
                self.getHex('bnew_x212'),
                self.getHex('mov_r1_r6'),
                self.getHex('movw_r4_x2e2'),
                self.getHex('ldrb_r0_r1_x10_!'),
                self.getHex('movt_r4_xe000'),
                self.getHex('ldrb_r2_r6_x11'),
                self.getHex('ldrb_r3_r1_3'),
                self.getHex('ldrb_r1_r1_2'),
                b'\x40\xea'
            )

            pattern2 = (
                self.getHex('ldr_r0_sp_x10'),
                self.getHex('bl_x4e2'),
                self.getHex('movw_r4_x2e2'),
                self.getHex('cmp_r0_0'),
                self.getHex('movt_r4_xe000'),
                self.getHex('bnew_x212'),
                self.getHex('mov_r1_r6'),
                b'\x40',
            )

            return joinPatterns(pattern1, pattern2)

        if self.version == '6.1.3':
            pattern1 = (
                self.getHex('bnew_x220'),
                self.getHex('ldr_r0_sp_x10'),
                self.getHex('bl_x4e2'),
                self.getHex('movw_r4_x2e2')
            )

            pattern2 = (
                self.getHex('cmp_r0_0'),
                self.getHex('movt_r4_xe000'),
                self.getHex('bnew_x212'),
                self.getHex('mov_r1_r6'),
                b'\x40\xf2'
            )

            return joinPatterns(pattern1, pattern2)

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
