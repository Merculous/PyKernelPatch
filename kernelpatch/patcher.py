
from .finder import Finder


class Patcher(Finder):
    def __init__(self, data: bytes):
        super().__init__(data)

    def allowFlashingUnsignedImg3ToNOR(self) -> None:
        # Applies patches to allow flashing unsigned
        # img3 to NOR. In this case, applies patches
        # to AppleImage3NORAccess.kext to enable this.

        MOVS_R0 = 'movs r0, #0'

        NOR = self.apple_image3_nor_access

        # PROD BL

        NOR[0].patch(f'{MOVS_R0}; {MOVS_R0}')

        # ECID BL

        NOR[1].patch(f'{MOVS_R0}; {MOVS_R0}')

        # SHSH CMP

        NOR[2].patch(MOVS_R0)

        # SHSH BL

        NOR[3].patch(f'{MOVS_R0}; {MOVS_R0}')

        # SHSH memmove BL

        NOR[4].patch(f'{MOVS_R0}; {MOVS_R0}')

        # RSA MOV

        NOR[5].patch(f'{MOVS_R0}; {MOVS_R0}')

        # AppleImage3NORAccess.kext patches done.
