
from .utils import joinBytePattern

ldr_r2_r4_x28 = b'\xa2\x6a'

ldr_r3_r3 = b'\x1b\x68'

mov_r3_1 = b'\x01\x23'

mov_r1_r5 = b'\x29\x46'

movs_r2_x13 = b'\x13\x22'

blx_r10 = b'\xd0\x47'

movs_r1_1 = b'\x01\x21'

cbz_r0_x14 = b'\x40\xb1'

adds_r5_x13 = b'\x13\x35'

movs_r2_1 = b'\x01\x22'

strw_r8_sp = b'\xcd\xf8\x00\x80'

strw_r8_sp_4 = b'\xcd\xf8\x04\x80'

str_r3_sp_8 = b'\x02\x93'

blx_r12 = b'\xe0\x47'

strw_r8_sp_8 = b'\xcd\xf8\x08\x80'

cmp_r0_0 = b'\x00\x28'

movs_r1_2 = b'\x02\x21'

ldr_r4_pc_x214 = b'\x85\x4c'

blx_r4 = b'\xa0\x47'

movs_r0_0 = b'\x00\x20'

bne_to_movw_r6_x2e2 = b'\xf2\xd1'  # 40 F2 E2 26

ldr_r0_sp_x14 = b'\x05\x98'

ldr_r4_pc_x20c = b'\x83\x4c'

ldr_r6_pc_xac = b'\x2b\x4e'

mov_r0_r5 = b'\x28\x46'

ldr_r1_sp_8 = b'\x02\x99'

blx_r6 = b'\xb0\x47'

subw_r4_r7_x18 = b'\xa7\xf1\x18\x04'

mov_r0_r1 = b'\x08\x46'

mov_sp_r4 = b'\xa5\x46'

cbnz_r0_x7c = b'\xc0\xbb'

it_ne = b'\x18\xbf'

movnew_r8_1 = b'\x4f\xf0\x01\x08'

mov_r0_r8 = b'\x40\x46'

add_sp_sp_x14 = b'\x05\xb0'

bne_to_movw_r6_x2e2_second = b'\xed\xd1'

movw_r1_neg1 = b'\x4f\xf0\xff\x31'  # MOVEQ.W         R1, #0xFFFFFFFF

popw_r8_r10_r11 = b'\xbd\xe8\x00\x0d'

cmp_r0_6 = b'\x06\x28'

andw_r0_r1_6 = b'\x01\xf0\x06\x00'

str_r1_sp_4 = b'\x01\x91'

bne_x16 = b'\x06\xd1'

blx_r2 = b'\x90\x47'

b_x23a = b'\x19\xe1'

cbz_r0_x12 = b'\x38\xb1'

ldr_r1_pc_x14 = b'\x05\x49'

ldr_r1_r1 = b'\x09\x68'

ldr_r0_pc_4 = b'\x01\x48'

ldr_r0_r0 = b'\x00\x68'

bx_lr = b'\x70\x47'

str_r1_r0 = b'\x01\x60'


class Pattern:
    def __init__(self, version):
        self.version = version

    def form_CSEnforcement(self):
        pattern = (
            ldr_r2_r4_x28,
            ldr_r3_r3
        )
        return (b''.join(pattern),)

    def form_AMFIMemcmp(self):
        if self.version == '5.0':
            pattern = (
                mov_r1_r5,
                movs_r2_x13,
                blx_r10,
                movs_r1_1
            )
            return (b''.join(pattern),)

        elif self.version == '5.0.1':
            pattern = (
                mov_r1_r5,
                movs_r2_x13,
                blx_r10,
                b'\x01'
            )
            return (b''.join(pattern),)

        elif self.version == '5.1':
            pattern = (
                mov_r1_r5,
                movs_r2_x13,
                blx_r10,
                movs_r1_1,
                cbz_r0_x14,
                adds_r5_x13,
                b'\x00'
            )
            return (b''.join(pattern),)

        elif self.version == '5.1.1':
            pattern = (
                mov_r1_r5,
                movs_r2_x13,
                blx_r10
            )
            return (b''.join(pattern),)

    def form_PE_i_can_has_debugger(self):
        if self.version == '5.1.1':
            pattern1 = (
                cbz_r0_x12,
                ldr_r1_pc_x14,
                ldr_r1_r1
            )

            pattern2 = (
                str_r1_r0,
                ldr_r0_pc_4,
                ldr_r0_r0,
                bx_lr
            )

            return (b''.join(pattern1), b''.join(pattern2))

    def form_AppleImage3NORAccess(self):
        if self.version == '5.1.1':
            pattern1 = (
                str_r3_sp_8,
                blx_r12,
                cbnz_r0_x7c
            )

            pattern2 = (
                strw_r8_sp_4,
                strw_r8_sp_8,
                blx_r12,
                cmp_r0_0
            )

            pattern3 = (
                ldr_r4_pc_x214,
                blx_r4,
                cmp_r0_0,
                bne_to_movw_r6_x2e2
            )

            pattern4 = (
                ldr_r4_pc_x20c,
                blx_r4,
                cmp_r0_0
            )

            pattern5 = (
                ldr_r1_sp_8,
                blx_r6,
                cmp_r0_0
            )

            patterns = (
                b''.join(pattern1),
                b''.join(pattern2),
                b''.join(pattern3),
                b''.join(pattern4),
                b''.join(pattern5),
            )

            return patterns

    def form_signatureCheck(self):
        if self.version == '5.0' or self.version == '5.0.1' or self.version == '5.1':
            pattern = (
                movw_r1_neg1,
                subw_r4_r7_x18,
                mov_r0_r1,
                mov_sp_r4,
                popw_r8_r10_r11,
                b'\xf0'
            )

        else:
            pattern = (
                movw_r1_neg1,
                subw_r4_r7_x18,
                mov_r0_r1,
                mov_sp_r4,
                popw_r8_r10_r11
            )

            return (b''.join(pattern),)

    def form_vm_map_enter(self):
        if self.version == '5.1.1':
            pattern = (
                andw_r0_r1_6,
                cmp_r0_6
            )

            return (b''.join(pattern),)

    def form_flush_dcache(self):
        pass

    def form_flush_icache(self):
        pass

    def form_tfp0(self):
        if self.version == '5.1.1':
            pattern = (
                str_r1_sp_4,
                bne_x16
            )

            return (b''.join(pattern),)

    def form_syscall0(self):
        pass

    def form_syscall0_value(self):
        pass

    def form_nx_enable(self):
        pass

    def form_io_log(self):
        pass

    def form_AMFIHook(self):
        if self.version == '5.1.1':
            pattern = (
                mov_r0_r5,
                blx_r2,
                b_x23a
            )

            return (b''.join(pattern),)
