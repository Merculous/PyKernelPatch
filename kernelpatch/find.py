
import struct

from armfind.find import (find_next_BL, find_next_blx_register,
                          find_next_CMP_with_value, find_next_LDR_Literal,
                          find_next_LDR_W_with_value, find_next_MOV_register,
                          find_next_MOV_W_with_value,
                          find_next_MOVT_with_value, find_next_MOVW_with_value,
                          find_next_pop, find_next_push)
from binpatch.types import Buffer
from binpatch.utils import getBufferAtIndex


class BaseClass:
    def __init__(self, data: Buffer, log: bool = True) -> None:
        self.data = data
        self.log = log
        self.loadAddr = struct.unpack('<I', getBufferAtIndex(self.data, 0x34, 4))[0]


class AppleImage3NORAccess3(BaseClass):
    def __init__(self, data: Buffer, log: bool = True) -> None:
        super().__init__(data, log)

        self.hwdinfo_from_image = self.find_hwdinfo_func()
        self.llb_decrypt_personalized = self.find_llb_decrypt_personalized()

    def find_hwdinfo_func(self) -> int:
        if self.log:
            print('find_hwdinfo_func()')

        ldrPROD = find_next_LDR_Literal(self.data, 0, 0, b'PROD'[::-1])

        if ldrPROD is None:
            raise Exception('Failed to find LDR Rx, PROD!')
        
        ldrPROD, ldrPRODOffset = ldrPROD

        if self.log:
            print(f'Found LDR Rx, PROD at {ldrPRODOffset:x}')

        push = find_next_push(self.data, ldrPRODOffset - 0x100, 0)

        if push is None:
            raise Exception('Failed to find PUSH!')

        push, pushOffset = push

        if self.log:
            print(f'Found PUSH at {pushOffset:x}')

        return pushOffset
    
    def find_hwdinfo_prod(self) -> int:
        if self.log:
            print('find_hwdinfo_prod()')

        ldrPROD = find_next_LDR_Literal(self.data, self.hwdinfo_from_image, 0, b'PROD'[::-1])

        if ldrPROD is None:
            raise Exception('Failed to find LDR Rx, PROD!')
        
        ldrPROD, ldrPRODOffset = ldrPROD

        if self.log:
            print(f'Found LDR Rx, PROD at {ldrPRODOffset:x}')

        bl = find_next_BL(self.data, ldrPRODOffset, 0)

        if bl is None:
            raise Exception('Failed to find BL!')

        bl, blOffset = bl

        if self.log:
            print(f'Found BL at {blOffset:x}')

        return blOffset
    
    def find_hwdinfo_ecid(self) -> int:
        if self.log:
            print('find_hwdinfo_ecid()')

        ldrECID = find_next_LDR_Literal(self.data, self.hwdinfo_from_image, 0, b'ECID'[::-1])

        if ldrECID is None:
            raise Exception('Failed to find LDR Rx, ECID!')
        
        ldrECID, ldrECIDOffset = ldrECID

        if self.log:
            print(f'Found LDR Rx, ECID at {ldrECIDOffset:x}')

        bl = find_next_BL(self.data, ldrECIDOffset, 0)

        if bl is None:
            raise Exception('Failed to find BL!')
        
        bl, blOffset = bl

        if self.log:
            print(f'Found BL at {blOffset:x}')

        return blOffset

    def find_llb_decrypt_personalized(self) -> int:
        if self.log:
            print('find_llb_decrypt_personalized()')

        movw = find_next_MOVW_with_value(self.data, self.hwdinfo_from_image, 0, 0x836)

        if movw is None:
            raise Exception('Failed to find MOVW Rx, #0x836!')

        movw, movwOffset = movw

        if self.log:
            print(f'Found MOVW Rx, #0x836 at {movwOffset:x}')

        push = find_next_push(self.data, movwOffset - 0x250, 0)

        if push is None:
            raise Exception('Failed to find PUSH!')

        push, pushOffset = push

        if self.log:
            print(f'Found PUSH at {pushOffset:x}')

        return pushOffset

    def find_image3_validate_check(self) -> int:
        if self.log:
            print('find_image3_validate_check()')

        ldrSHSH = find_next_LDR_Literal(self.data, self.llb_decrypt_personalized, 0, b'SHSH'[::-1])

        if ldrSHSH is None:
            raise Exception('Failed to find LDR Rx, SHSH!')

        ldrSHSH, ldrSHSHOffset = ldrSHSH

        if self.log:
            print(f'Found LDR Rx, SHSH at {ldrSHSHOffset:x}')

        cmp = find_next_CMP_with_value(self.data, ldrSHSHOffset, 1, 0)

        if cmp is None:
            raise Exception('Failed to find CMP Rx, #0!')

        cmp, cmpOffset = cmp

        if self.log:
            print(f'Found CMP Rx, #0 at {cmpOffset:x}')

        return cmpOffset

    def find_hwdinfo_check(self) -> int:
        if self.log:
            print(f'find_hwdinfo_check()')

        ldrSHSH = find_next_LDR_Literal(self.data, self.llb_decrypt_personalized, 0, b'SHSH'[::-1])

        if ldrSHSH is None:
            raise Exception('Failed to find LDR Rx, SHSH!')

        ldrSHSH, ldrSHSHOffset = ldrSHSH

        if self.log:
            print(f'Found LDR Rx, SHSH at {ldrSHSHOffset:x}')

        bl = find_next_BL(self.data, ldrSHSHOffset, 0)

        if bl is None:
            raise Exception('Failed to find BL!')

        bl, blOffset = bl

        if self.log:
            print(f'Found BL at {blOffset:x}')

        cmp = find_next_CMP_with_value(self.data, blOffset, 0, 0)

        if cmp is None:
            raise Exception('Failed to find CMP Rx, #0!')

        cmp, cmpOffset = cmp

        if self.log:
            print(f'Found CMP Rx, #0 at {cmpOffset:x}')

        return cmpOffset

    def find_shsh_encrypt(self) -> int:
        if self.log:
            print('find_shsh_encrypt()')

        movw = find_next_MOVW_with_value(self.data, self.llb_decrypt_personalized, 0, 0x836)

        if movw is None:
            raise Exception('Failed to find MOVW Rx, #0x836!')
        
        movw, movwOffset = movw

        if self.log:
            print(f'Found MOVW Rx, #0x836 at {movwOffset:x}')

        bl = find_next_BL(self.data, movwOffset, 2)

        if bl is None:
            raise Exception('Failed to find BL!')
        
        bl, blOffset = bl

        if self.log:
            print(f'Found BL at {blOffset:x}')

        return blOffset


    def find_pk_verify_sha1(self) -> int:
        if self.log:
            print('find_pk_verify_sha1()')

        movw = find_next_MOVW_with_value(self.data, self.llb_decrypt_personalized, 0, 0x4BF)

        if movw is None:
            raise Exception('Failed to find MOVW Rx, #0x4BF!')

        movw, movwOffset = movw

        if self.log:
            print(f'Found MOVW Rx, #0x4BF at {movwOffset:x}')

        movw_w = find_next_MOV_W_with_value(self.data, movwOffset, 0, 0x3FF)

        if movw_w is None:
            raise Exception('Failed to find MOV.W Rx, #0xFFFFFFFF')

        movw_w, movw_wOffset = movw_w

        if self.log:
            print(f'Found MOV.W Rx, #0xFFFFFFFF at {movw_wOffset:x}')

        return movw_wOffset


class AppleImage3NORAccess4(AppleImage3NORAccess3):
    def __init__(self, data: Buffer, log: bool = True) -> None:
        super().__init__(data, log)

    def find_hwdinfo_func(self) -> int:
        if self.log:
            print('find_hwdinfo_func()')

        ldrPROD = find_next_LDR_W_with_value(self.data, 0, 0, b'PROD'[::-1])

        if ldrPROD is None:
            raise Exception('Failed to find LDR.W Rx, PROD!')
        
        ldrPROD, ldrPRODOffset = ldrPROD

        if self.log:
            print(f'Found LDR.W Rx, PROD at {ldrPRODOffset:x}')

        push = find_next_push(self.data, ldrPRODOffset - 0x100, 0)

        if push is None:
            raise Exception('Failed to find PUSH!')

        push, pushOffset = push

        if self.log:
            print(f'Found PUSH at {pushOffset:x}')

        return pushOffset

    def find_hwdinfo_prod(self) -> int:
        if self.log:
            print('find_hwdinfo_prod()')

        ldrPROD = find_next_LDR_W_with_value(self.data, 0, 0, b'PROD'[::-1])

        if ldrPROD is None:
            raise Exception('Failed to find LDR.W Rx, PROD!')
        
        ldrPROD, ldrPRODOffset = ldrPROD

        if self.log:
            print(f'Found LDR.W Rx, PROD at {ldrPRODOffset:x}')

        bl = find_next_BL(self.data, ldrPRODOffset, 0)

        if bl is None:
            raise Exception('Failed to find Bl!')
        
        bl, blOffset = bl

        if self.log:
            print(f'Found BL at {blOffset:x}')

        return blOffset


class AppleImage3NORAccess5(AppleImage3NORAccess4):
    def __init__(self, data: Buffer, log: bool = True) -> None:
        super().__init__(data, log)

    def find_hwdinfo_func(self) -> int:
        if self.log:
            print('find_hwdinfo_func()')

        movt = find_next_MOVT_with_value(self.data, 0, 1, int.from_bytes(b'PR'))

        if movt is None:
            raise Exception('Failed to find MOVT Rx, PR!')

        movt, movtOffset = movt

        if self.log:
            print(f'Found MOVT Rx, PR at {movtOffset:x}')

        push = find_next_push(self.data, movtOffset - 0x150, 0)

        if push is None:
            raise Exception('Failed to find PUSH!')

        push, pushOffset = push

        if self.log:
            print(f'Found PUSH at {pushOffset:x}')

        return pushOffset

    def find_hwdinfo_prod(self) -> int:
        if self.log:
            print('find_hwdinfo_prod()')

        movt = find_next_MOVT_with_value(self.data, self.hwdinfo_from_image, 0, int.from_bytes(b'PR'))

        if movt is None:
            raise Exception('Failed to find MOVT Rx, PR!')

        movt, movtOffset = movt

        if self.log:
            print(f'Found MOVT Rx, PR at {movtOffset:x}')

        blx = find_next_blx_register(self.data, movtOffset, 0)

        if blx is None:
            raise Exception('Failed to find BLX!')

        blx, blxOffset = blx

        if self.log:
            print(f'Found BLX at {blxOffset:x}')

        return blxOffset

    def find_hwdinfo_ecid(self) -> int:
        if self.log:
            print('find_hwdinfo_ecid()')

        movt = find_next_MOVT_with_value(self.data, self.hwdinfo_from_image, 0, int.from_bytes(b'EC'))

        if movt is None:
            raise Exception('Failed to find MOVT Rx, EC!')
        
        movt, movtOffset = movt

        if self.log:
            print(f'Found MOVT Rx, EC at {movtOffset:x}')

        blx = find_next_blx_register(self.data, movtOffset, 0)

        if blx is None:
            raise Exception('Failed to find BLX!')
        
        blx, blxOffset = blx

        if self.log:
            print(f'Found BLX at {blxOffset:x}')

        return blxOffset

    def find_llb_decrypt_personalized(self) -> int:
        if self.log:
            print('llb_decrypt_personalized()')

        movt = find_next_MOVT_with_value(self.data, self.hwdinfo_from_image, 2, int.from_bytes(b'SH'))

        if movt is None:
            raise Exception('Failed to find MOVT Rx, SH!')
        
        movt, movtOffset = movt

        if self.log:
            print(f'Found MOVT Rx, SH at {movtOffset:x}')

        push = find_next_push(self.data, movtOffset - 0xD0, 0)

        if push is None:
            raise Exception('Failed to find PUSH!')
        
        push, pushOffset = push

        if self.log:
            print(f'Found PUSH at {pushOffset:x}')

        return pushOffset

    def find_image3_validate_check(self) -> int:
        if self.log:
            print('find_image3_validate_check()')

        movt = find_next_MOVT_with_value(self.data, self.llb_decrypt_personalized, 0, int.from_bytes(b'SH'))

        if movt is None:
            raise Exception('Failed to find MOVT Rx, SH!')
        
        movt, movtOffset = movt

        if self.log:
            print(f'Found MOVT Rx, SH at {movtOffset:x}')

        blx = find_next_blx_register(self.data, movtOffset, 1)

        if blx is None:
            raise Exception('Failed to find BLX!')
        
        blx, blxOffset = blx

        if self.log:
            print(f'Found BLX at {blxOffset:x}')

        cmp = find_next_CMP_with_value(self.data, blxOffset, 0, 0)

        if cmp is None:
            raise Exception('Failed to find CMP Rx, #0!')
        
        cmp, cmpOffset = cmp

        if self.log:
            print(f'Found CMP Rx, #0 at {cmpOffset:x}')

        return cmpOffset

    def find_hwdinfo_check(self) -> int:
        if self.log:
            print('find_hwdinfo_check()')

        movt = find_next_MOVT_with_value(self.data, self.llb_decrypt_personalized, 0, int.from_bytes(b'SH'))

        if movt is None:
            raise Exception('Failed to find MOVT Rx, SH!')
        
        movt, movtOffset = movt

        if self.log:
            print(f'Found MOVT Rx, SH at {movtOffset:x}')

        blx = find_next_blx_register(self.data, movtOffset, 2)

        if blx is None:
            raise Exception('Failed to find BLX!')
        
        blx, blxOffset = blx

        if self.log:
            print(f'Found BLX at {blxOffset:x}')

        cmp = find_next_CMP_with_value(self.data, blxOffset, 0, 0)

        if cmp is None:
            raise Exception('Failed to find CMP Rx, #0!')
        
        cmp, cmpOffset = cmp

        if self.log:
            print(f'Found CMP Rx, #0 at {cmpOffset:x}')

        return cmpOffset

    def find_shsh_encrypt(self) -> int:
        if self.log:
            print('find_shsh_encrypt()')

        movw = find_next_MOVW_with_value(self.data, self.llb_decrypt_personalized, 0, 0x836)

        if movw is None:
            raise Exception('Failed to find MOVW Rx, #0x836!')
        
        movw, movwOffset = movw

        if self.log:
            print(f'Found MOVW Rx, #0x836 at {movwOffset:x}')

        blx = find_next_blx_register(self.data, movwOffset, 3)

        if blx is None:
            raise Exception('Failed to find BLX!')
        
        blx, blxOffset = blx

        if self.log:
            print(f'Found BLX at {blxOffset:x}')

        return blxOffset

    def find_pk_verify_sha1(self) -> int:
        if self.log:
            print('find_pk_verify_sha1()')

        movw = find_next_MOVW_with_value(self.data, self.llb_decrypt_personalized, 0, 0x4BF)

        if movw is None:
            raise Exception('Failed to find MOVW Rx, #0x4BF!')

        movw, movwOffset = movw

        if self.log:
            print(f'Found MOVW Rx, 0x4BF at {movwOffset:x}')

        pop = find_next_pop(self.data, movwOffset, 0)

        if pop is None:
            raise Exception('Failed to find POP!')

        pop, popOffset = pop

        if self.log:
            print(f'Found POP at {popOffset:x}')

        mov = find_next_MOV_register(self.data, popOffset - 0x10, 0)

        if mov is None:
            raise Exception('Failed to find MOV Rx, Rx!')

        mov, movOffset = mov

        if self.log:
            print(f'Found MOV Rx, Rx at {movOffset:x}')

        return movOffset
