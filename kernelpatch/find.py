
from armfind.find import (find_next_BL, find_next_blx_register,
                          find_next_CMP_with_value, find_next_LDR_Literal,
                          find_next_LDR_W_with_value, find_next_MOV_register,
                          find_next_MOV_W_with_value,
                          find_next_MOVT_with_value, find_next_MOVW_with_value,
                          find_next_pop)
from binpatch.types import Buffer


class BaseClass:
    def __init__(self, data: Buffer, version: int, log: bool = True) -> None:
        self._data = data
        self.log = log
        self.version = version

    def getiOSVersion(self) -> None:
        pass


class AppleImage3NORAccess(BaseClass):
    def __init__(self, data: Buffer, version: int, log: bool = True) -> None:
        super().__init__(data, version, log)

        self.kextStart = self.getKextStart()

    def getKextStart(self) -> int:
        kModStr = b'com.apple.driver.AppleImage3NORAccess'
        kModStrOffset = self._data.find(kModStr)

        if kModStrOffset == -1:
            raise Exception(f'Failed to find {kModStr.decode()}')

        if self.log:
            print(f'Found {kModStr.decode()} at {kModStrOffset:x}')

        # Adjust offset a bit (hacky)
        kModStrOffset -= 0x10000
        return kModStrOffset


    def find_hwdinfo_prod(self) -> int:
        insn = None

        if self.version in (3, 4):
            if self.version == 3:
                insn = find_next_LDR_Literal(self._data, self.kextStart, 0, b'PROD'[::-1])
            else:
                insn = find_next_LDR_W_with_value(self._data, self.kextStart, 0, b'PROD'[::-1])

            if insn is None:
                raise Exception('Failed to find LDR(.W)!')

            insn, insnOffset = insn

            if self.log:
                print(f'Found LDR(.W) Rx, PROD at {insnOffset:x}')

            bl = find_next_BL(self._data, insnOffset, 0)

            if bl is None:
                raise Exception('Failed to find BL!')

            bl, blOffset = bl

            if self.log:
                print(f'Found BL at {blOffset:x}')

            return blOffset

        elif self.version == 5:
            insn = find_next_MOVT_with_value(self._data, self.kextStart, 0, 0x5052)

            if insn is None:
                raise Exception('Failed to find MOVT Rx, PR!')

            insn, insnOffset = insn

            if self.log:
                print(f'Found MOVT Rx, PR at {insnOffset:x}')

            blx = find_next_blx_register(self._data, insnOffset, 0)

            if blx is None:
                raise Exception('Failed to find BLX!')

            blx, blxOffset = blx

            if self.log:
                print(f'Found BLX at {blxOffset:x}')

            return blxOffset

        else:
            raise Exception('UNIMPLEMENTED')

    def find_hwdinfo_ecid(self) -> int:
        insn = None

        if self.version in (3, 4):
            insn = find_next_LDR_Literal(self._data, self.kextStart, 0 , b'ECID'[::-1])

            if insn is None:
                raise Exception('Failed to find LDR(.W) Rx, ECID!')

            insn, insnOffset = insn

            if self.log:
                print(f'Found LDR(.W) Rx, ECID at {insnOffset:x}')

            bl = find_next_BL(self._data, insnOffset, 0)

            if bl is None:
                raise Exception('Failed to find BL!')

            bl, blOffset = bl

            if self.log:
                print(f'Found BL at {blOffset:x}')

            return blOffset

        elif self.version == 5:
            insn = find_next_MOVT_with_value(self._data, self.kextStart, 0, 0x4543)

            if insn is None:
                raise Exception('Failed to find MOVT Rx, EC!')

            insn, insnOffset = insn

            if self.log:
                print(f'Found MOVT Rx, EC at {insnOffset:x}')

            blx = find_next_blx_register(self._data, insnOffset, 0)

            if blx is None:
                raise Exception('Failed to BLX!')

            blx, blxOffset = blx

            if self.log:
                print(f'Found BLX at {blxOffset:x}')

            return blxOffset

        else:
            raise Exception('UNIMPLEMENTED')

    def find_validate_check(self) -> int:
        insn = None

        if self.version in (3, 4):
            insn = find_next_LDR_Literal(self._data, self.kextStart, 2, b'SHSH'[::-1])

            if insn is None:
                raise Exception('Failed to find LDR Rx, SHSH!')

            insn, insnOffset = insn

            if self.log:
                print(f'Found LDR Rx, SHSH at {insnOffset:x}')

            cmp = find_next_CMP_with_value(self._data, insnOffset, 1, 0)

            if cmp is None:
                raise Exception('Failed to find CMP Rx, #0!')

            cmp, cmpOffset = cmp

            if self.log:
                print(f'Found CMP Rx, #0 at {cmpOffset:x}')

            return cmpOffset

        elif self.version == 5:
            insn = find_next_MOVT_with_value(self._data, self.kextStart, 2, 0x5348)

            if insn is None:
                raise Exception('Failed to find MOVT Rx, SH!')

            insn, insnOffset = insn

            if self.log:
                print(f'Found MOVT Rx, SH at {insnOffset:x}')

            cmp = find_next_CMP_with_value(self._data, insnOffset, 0, 0)

            if cmp is None:
                raise Exception('Failed to find CMP Rx, #0!')

            cmp, cmpOffset = cmp

            if self.log:
                print(f'Found CMP Rx, #0 at {cmpOffset:x}')

            return cmpOffset

        else:
            raise Exception('UNIMPLEMENTED')

    def find_hwdinfo_check(self) -> int:
        insn = None

        if self.version in (3, 4):
            insn = find_next_LDR_Literal(self._data, self.kextStart, 2, b'SHSH'[::-1])

            if insn is None:
                raise Exception('Failed to find LDR Rx, SHSH!')

            insn, insnOffset = insn

            if self.log:
                print(f'Found LDR Rx, SHSH at {insnOffset:x}')

            cmp = find_next_CMP_with_value(self._data, insnOffset, 2, 0)

            if cmp is None:
                raise Exception('Failed to find CMP Rx, #0!')

            cmp, cmpOffset = cmp

            if self.log:
                print(f'Found CMP Rx, #0 at {cmpOffset:x}')

            return cmpOffset

        elif self.version == 5:
            insn = find_next_MOVT_with_value(self._data, self.kextStart, 2, 0x5348)

            if insn is None:
                raise Exception('Failed to find MOVT Rx, SH!')

            insn, insnOffset = insn

            if self.log:
                print(f'Found MOVT Rx, SH at {insnOffset:x}')

            cmp = find_next_CMP_with_value(self._data, insnOffset, 1, 0)

            if cmp is None:
                raise Exception('Failed to find CMP Rx, #0!')

            cmp, cmpOffset = cmp

            if self.log:
                print(f'Found CMP Rx, #0 at {cmpOffset:x}')

            return cmpOffset

        else:
            raise Exception('UNIMPLEMENTED')

    def find_shsh_encrypt(self) -> int:
        insn = None

        if self.version in (3, 4):
            insn = find_next_LDR_Literal(self._data, self.kextStart, 2, b'SHSH'[::-1])

            if insn is None:
                raise Exception('Failed to find LDR Rx, SHSH!')

            insn, insnOffset = insn

            if self.log:
                print(f'Found LDR Rx, SHSH at {insnOffset:x}')

            movw = find_next_MOVW_with_value(self._data, insnOffset, 0, 0x836)

            if movw is None:
                raise Exception('Failed to find MOVW Rx, #0x836!')

            movw, movwOffset = movw

            if self.log:
                print(f'Found MOVW Rx, #0x836 at {movwOffset:x}')

            bl = find_next_BL(self._data, movwOffset, 2)

            if bl is None:
                raise Exception('Failed to find BL!')

            bl, blOffset = bl

            if self.log:
                print(f'Found BL at {blOffset:x}')

            return blOffset

        elif self.version == 5:
            insn = find_next_MOVT_with_value(self._data, self.kextStart, 2, 0x5348)

            if insn is None:
                raise Exception('Failed to find MOVT Rx, SH!')

            insn, insnOffset = insn

            if self.log:
                print(f'Found MOVT Rx, SH at {insnOffset:x}')

            movw = find_next_MOVW_with_value(self._data, insnOffset, 0, 0x836)

            if movw is None:
                raise Exception('Failed to find MOVW Rx, #0x836!')

            movw, movwOffset = movw

            if self.log:
                print(f'Found MOVW Rx, #0x836 at {movwOffset:x}')

            blx = find_next_blx_register(self._data, movwOffset, 3)

            if blx is None:
                raise Exception('Failed to find BLX!')
            
            blx, blxOffset = blx

            if self.log:
                print(f'Found BLX at {blxOffset:x}')

            return blxOffset

        else:
            raise Exception('UNIMPLEMENTED')

    def find_pk_verify_sha1(self) -> int:
        insn = find_next_MOVW_with_value(self._data, self.kextStart, 0, 0x4BF)

        if insn is None:
            raise Exception('Failed to find MOVW Rx, #0x4BF!')
        
        insn, insnOffset = insn

        if self.log:
            print(f'Found MOVW Rx, #0x4BF at {insnOffset:x}')

        if self.version in (3, 4):
            movw = find_next_MOV_W_with_value(self._data, insnOffset, 0, 0x3FF)

            if movw is None:
                raise Exception('Failed to find MOV.W Rx, #0xFFFFFFFF!')
            
            movw, movwOffset = movw

            if self.log:
                print(f'Found MOV.W Rx, #0xFFFFFFFF at {movwOffset:x}')

            return movwOffset
        
        elif self.version == 5:
            pop = find_next_pop(self._data, insnOffset, 0)

            if pop is None:
                raise Exception('Failed to find POP!')
            
            pop, popOffset = pop

            if self.log:
                print(f'Found POP at {popOffset:x}')

            mov = find_next_MOV_register(self._data, popOffset - 0x10, 0)

            if mov is None:
                raise Exception('Failed to find MOV Rx, Rx!')

            mov, movOffset = mov

            if self.log:
                print(f'Found MOV Rx, Rx at {movOffset:x}')

            return movOffset

        else:
            raise Exception('UNIMPLEMENTED')
