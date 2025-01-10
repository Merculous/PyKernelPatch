
from binpatch.types import Buffer
from binpatch.utils import replaceBufferAtIndex

from .find import (AppleImage3NORAccess3, AppleImage3NORAccess4,
                   AppleImage3NORAccess5, AppleImage3NORAccess6)


class NORPatcher3(AppleImage3NORAccess3):
    def __init__(self, data: Buffer, log: bool = True) -> None:
        super().__init__(data, log)

    def patch_hwdinfo_prod(self) -> None:
        offset = self.find_hwdinfo_prod()
        self.data = replaceBufferAtIndex(self.data, b'\x00\x20\x00\x20', offset, 4)

    def patch_hwdinfo_ecid(self) -> None:
        offset = self.find_hwdinfo_ecid()
        self.data = replaceBufferAtIndex(self.data, b'\x00\x20\x00\x20', offset, 4)

    def patch_image3_validate_check(self) -> None:
        offset = self.find_image3_validate_check()
        self.data = replaceBufferAtIndex(self.data, b'\x00\x20', offset, 2)

    def patch_hwdinfo_check(self) -> None:
        offset = self.find_hwdinfo_check()
        self.data = replaceBufferAtIndex(self.data, b'\x00\x20', offset, 2)

    def patch_shsh_encrypt(self) -> None:
        offset = self.find_shsh_encrypt()
        self.data = replaceBufferAtIndex(self.data, b'\x01\x20\x01\x20', offset, 4)

    def patch_pk_verify_sha1(self) -> None:
        offset = self.find_pk_verify_sha1()
        self.data = replaceBufferAtIndex(self.data, b'\x00\x20\x00\x20', offset, 4)


class NORPatcher4(NORPatcher3, AppleImage3NORAccess4):
    pass


class NORPatcher5(NORPatcher4, AppleImage3NORAccess5):
    def patch_hwdinfo_prod(self) -> None:
        offset = self.find_hwdinfo_prod()
        self.data = replaceBufferAtIndex(self.data, b'\x00\x20', offset, 2)

    def patch_hwdinfo_ecid(self) -> None:
        offset = self.find_hwdinfo_ecid()
        self.data = replaceBufferAtIndex(self.data, b'\x00\x20', offset, 2)

    def patch_shsh_encrypt(self) -> None:
        offset = self.find_shsh_encrypt()
        self.data = replaceBufferAtIndex(self.data, b'\x01\x20', offset, 2)

    def patch_pk_verify_sha1(self) -> None:
        offset = self.find_pk_verify_sha1()
        self.data = replaceBufferAtIndex(self.data, b'\x00\x20', offset, 2)


class NORPatcher6(NORPatcher5, AppleImage3NORAccess6):
    pass
