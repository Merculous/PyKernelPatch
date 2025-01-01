
from binpatch.types import Buffer
from binpatch.utils import replaceBufferAtIndex

from .find import AppleImage3NORAccess

class NORPatcher(AppleImage3NORAccess):
    def __init__(self, data: Buffer, log: bool = True) -> None:
        super().__init__(data, log)

    def patch_hwdinfo_prod(self) -> None:
        offset = self.find_hwdinfo_prod()
        self.data = replaceBufferAtIndex(self.data, b'\x00\x20\x00\x20', offset, 4)

    def patch_hwdinfo_ecid(self) -> None:
        offset = self.find_hwdinfo_ecid()
        self.data = replaceBufferAtIndex(self.data, b'\x00\x20\x00\x20', offset, 4)

    def patch_image3_validate(self) -> None:
        offset = self.find_image3_validate()
        self.data = replaceBufferAtIndex(self.data, b'\x00\x20', offset, 2)

    def patch_hwdinfo_func(self) -> None:
        offset = self.find_hwdinfo_func()
        self.data = replaceBufferAtIndex(self.data, b'\x00\x20', offset, 2)

    def patch_shsh_encrypt(self) -> None:
        offset = self.find_shsh_encrypt()
        self.data = replaceBufferAtIndex(self.data, b'\x01\x20\x01\x20', offset, 4)

    def patch_pk_verify_sha1(self) -> None:
        offset = self.find_pk_verify_SHA1()
        self.data = replaceBufferAtIndex(self.data, b'\x00\x20\x00\x20', offset, 4)
