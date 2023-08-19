
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


class Pattern:
    def __init__(self, version):
        self.version = version

    def CSEnforcement(self):
        pattern = (
            ldr_r2_r4_x28,
            ldr_r3_r3
        )
        return (b''.join(pattern),)

    def AMFIMemcmp(self):
        if self.version == '5.0' or self.version == '5.0.1':
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

    def PE_i_can_has_debugger(self):
        if self.version == '5.0' or self.version == '5.0.1':
            pattern1 = (
                b'\x00\x80',
                strw_r8_sp_4,
                str_r3_sp_8,
                blx_r12,
                cbnz_r0_x7c
            )

            pattern2 = (
                blx_r12,
                cmp_r0_0,
                it_ne,
                movnew_r8_1,
                mov_r0_r8,
                add_sp_sp_x14
            )

            return (b''.join(pattern1), b''.join(pattern2))

        elif self.version == '5.1':
            pattern1 = (
                b'\x00\x80',
                strw_r8_sp_4,
                str_r3_sp_8,
                blx_r12,
                cbnz_r0_x7c
            )

            pattern2 = (
                strw_r8_sp_4,
                strw_r8_sp_8,
                blx_r12,
                cmp_r0_0,
                b'\x18'
            )

            return (b''.join(pattern1), b''.join(pattern2))

        elif self.version == '5.1.1':
            pattern1 = (
                movs_r2_1,
                strw_r8_sp,
                strw_r8_sp_4,
                str_r3_sp_8,
                blx_r12,
                b'\xc0'
            )

            pattern2 = (
                strw_r8_sp,
                strw_r8_sp_4,
                strw_r8_sp_8,
                blx_r12,
                cmp_r0_0,
                b'\x18'
            )

            return (b''.join(pattern1), b''.join(pattern2))

    def AppleImage3NORAccess(self):
        if self.version == '5.0' or self.version == '5.0.1' or self.version == '5.1':
            pattern1 = (
                movs_r1_2,
                ldr_r4_pc_x214,
                blx_r4,
                cmp_r0_0
            )

            pattern2 = (
                bne_to_movw_r6_x2e2,
                ldr_r0_sp_x14,
                ldr_r4_pc_x20c,
                blx_r4,
                cmp_r0_0,
                bne_to_movw_r6_x2e2_second
            )

            # Fails on 5.0 and 5.1

            pattern3 = (
                ldr_r6_pc_xac,
                mov_r0_r5,
                ldr_r1_sp_8,
                blx_r6
            )

            # Fails on 5.0.1

            pattern4 = (
                movw_r1_neg1,
                subw_r4_r7_x18,
                mov_r0_r1,
                mov_sp_r4,
                popw_r8_r10_r11
            )

            return (b''.join(pattern1), b''.join(pattern2), b''.join(pattern3), b''.join(pattern4))

        elif self.version == '5.1.1':
            pattern1 = (
                movs_r1_2,
                ldr_r4_pc_x214,
                blx_r4,
                cmp_r0_0
            )

            pattern2 = (
                bne_to_movw_r6_x2e2,
                ldr_r0_sp_x14,
                ldr_r4_pc_x20c,
                blx_r4,
                cmp_r0_0
            )

            pattern3 = (
                ldr_r6_pc_xac,
                mov_r0_r5,
                ldr_r1_sp_8,
                blx_r6
            )

            pattern4 = (
                subw_r4_r7_x18,
                mov_r0_r1,
                mov_sp_r4,
                b'\xbd\xe8'
            )

            return (b''.join(pattern1), b''.join(pattern2), b''.join(pattern3), b''.join(pattern4))
