
import struct

from armfind.find import (
    find_next_LDR_Literal,
    find_next_BL,
    find_next_CMP_with_value,
    find_next_MOV_W_with_value,
    find_next_MOVW_with_value,
    find_next_push
)
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

        ldrillb = find_next_LDR_Literal(self.data, 0, 2, b'illb'[::-1])

        if ldrillb is None:
            raise Exception('Failed to find LDR Rx, illb!')

        ldrillb, ldrillbOffset = ldrillb

        if self.log:
            print(f'Found LDR Rx, SHSH at {ldrillbOffset:x}')

        push = find_next_push(self.data, ldrillbOffset - 0x100, 0)

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

        cmp = find_next_CMP_with_value(self.data, ldrSHSHOffset, 2, 0)

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
