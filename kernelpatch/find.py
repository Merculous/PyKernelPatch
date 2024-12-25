
from armfind.find import (
    find_next_LDR_Literal,
    find_next_BL,
    find_next_CMP_with_value,
    find_next_MOV_W_with_value,
    find_next_MOVW_with_value
)
from binpatch.types import Buffer


class AppleImage3NORAccess:
    def __init__(self, data: Buffer, log: bool = True) -> None:
        self.data = data
        self.log = log

    def find_hwdinfo_prod(self) -> int:
        if self.log:
            print('find_hwdinfo_prod()')

        ldrPROD = find_next_LDR_Literal(self.data, 0, 0, b'PROD'[::-1])

        if ldrPROD is None:
            raise Exception('Failed to find LDR Rx, PROD!')

        ldrPROD, ldrPRODOffset = ldrPROD

        if self.log:
            print(f'Found LDR Rx, PROD at: {ldrPRODOffset:x}')

        bl = find_next_BL(self.data, ldrPRODOffset, 0)

        if bl is None:
            raise Exception('Failed to find next Bl!')

        bl, blOffset = bl

        if self.log:
            print(f'Found BL at: {blOffset:x}')

        return blOffset

    def find_hwdinfo_ecid(self) -> int:
        if self.log:
            print('find_hwdinfo_ecid()')

        ldrECID = find_next_LDR_Literal(self.data, 0, 0, b'ECID'[::-1])

        if ldrECID is None:
            raise Exception('Failed to find LDR Rx, ECID!')
        
        ldrECID, ldrECIDOffset = ldrECID

        if self.log:
            print(f'Found LDR Rx, ECID at: {ldrECIDOffset:x}')

        bl = find_next_BL(self.data, ldrECIDOffset, 0)

        if bl is None:
            raise Exception('Failed to find next BL!')

        bl, blOffset = bl

        if self.log:
            print(f'Found BL at: {blOffset:x}')

        return blOffset

    def find_image3_validate(self) -> int:
        if self.log:
            print('find_image3_validate()')

        ldrSHSH = find_next_LDR_Literal(self.data, 0, 4, b'SHSH'[::-1])
 
        if ldrSHSH is None:
            raise Exception('Failed to find LDR Rx, SHSH!')
        
        ldrSHSH, ldrSHSHOffset = ldrSHSH

        if self.log:
            print(f'Found LDR Rx, SHSH at: {ldrSHSHOffset:x}')

        cmp = find_next_CMP_with_value(self.data, ldrSHSHOffset, 1, 0)

        if cmp is None:
            raise Exception('Failed to find CMP, Rx #0!')

        cmp, cmpOffset = cmp

        if self.log:
            print(f'Found CMP Rx, #0 at: {cmpOffset:x}')

        return cmpOffset


    def find_hwdinfo_func(self) -> int:
        if self.log:
            print('find_hwdinfo_func()')

        ldrLLB = find_next_LDR_Literal(self.data, 0, 3, b'illb'[::-1])

        if ldrLLB is None:
            raise Exception('Failed to find LDR, Rx illb!')
        
        ldrLLB, ldrLLBOffset = ldrLLB

        if self.log:
            print(f'Found LDR Rx, illb at: {ldrLLBOffset:x}')

        cmp = find_next_CMP_with_value(self.data, ldrLLBOffset - 10, 0, 0)

        if cmp is None:
            raise Exception('Failed to find CMP Rx, #0!')

        cmp, cmpOffset = cmp

        if self.log:
            print(f'Found CMP Rx, #0 at: {cmpOffset:x}')

        return cmpOffset


    def find_shsh_encrypt(self) -> int:
        if self.log:
            print('find_shsh_encrypt()')

        movw = find_next_MOVW_with_value(self.data, 0, 1, 0x836)

        if movw is None:
            raise Exception('Failed to find MOVW Rx, #0x836')

        movw, movwOffset = movw

        if self.log:
            print(f'Found MOVW Rx, #0x836 at: {movwOffset:x}')

        bl = find_next_BL(self.data, movwOffset, 2)

        if bl is None:
            raise Exception('Failed to find next Bl!')

        bl, blOffset = bl

        if self.log:
            print(f'Found BL at: {blOffset:x}')

        return blOffset


    def find_pk_verify_SHA1(self) -> int:
        if self.log:
            print('find_pk_verify_SHA1()')
        
        movw = find_next_MOVW_with_value(self.data, 0, 2, 0x4BF)

        if movw is None:
            raise Exception('Failed to find MOVW Rx, #0x4BF')
        
        movw, movwOffset = movw

        if self.log:
            print(f'Found MOVW Rx, #0x4BF at: {movwOffset:x}')

        mov_w = find_next_MOV_W_with_value(self.data, movwOffset, 0, 0x3FF)

        if mov_w is None:
            raise Exception('Failed to find MOV.W Rx, #0xFFFFFFFF')

        mov_w, mov_wOffset = mov_w

        if self.log:
            print(f'Found MOV.W Rx, #0xFFFFFFFF at: {mov_wOffset:x}')

        return mov_wOffset
