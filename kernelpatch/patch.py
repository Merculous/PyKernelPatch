
from binpatch.types import Buffer
from binpatch.utils import replaceBufferAtIndex

from .find import AppleImage3NORAccess


class AppleImage3NORAccessPatcher(AppleImage3NORAccess):
    def __init__(self, data: Buffer, version: int, log: bool = True) -> None:
        super().__init__(data, version, log)

        self.patchedData = self._data[:]

    def patch_hwdinfo_prod(self) -> None:
        offset = self.find_hwdinfo_prod()

        if self.version in (3, 4):
            self.patchedData = replaceBufferAtIndex(self.patchedData, b'\x00\x20\x00\x20', offset, 4)
        elif self.version == 5:
            self.patchedData = replaceBufferAtIndex(self.patchedData, b'\x00\x20', offset, 2)
        else:
            raise Exception('UNIMPLEMENTED!')

    def patch_hwdinfo_ecid(self) -> None:
        offset = self.find_hwdinfo_ecid()

        if self.version in (3, 4):
            self.patchedData = replaceBufferAtIndex(self.patchedData, b'\x00\x20\x00\x20', offset, 4)
        elif self.version == 5:
            self.patchedData = replaceBufferAtIndex(self.patchedData, b'\x00\x20', offset, 2)
        else:
            raise Exception('UNIMPLEMENTED!')
        

    def patch_validate_check(self) -> None:
        offset = self.find_validate_check()
        self.patchedData = replaceBufferAtIndex(self.patchedData, b'\x00\x20', offset, 2)

    def patch_hwdinfo_check(self) -> None:
        offset = self.find_hwdinfo_check()
        self.patchedData = replaceBufferAtIndex(self.patchedData, b'\x00\x20', offset, 2)

    def patch_shsh_encrypt(self) -> None:
        offset = self.find_shsh_encrypt()

        if self.version in (3, 4):
            self.patchedData = replaceBufferAtIndex(self.patchedData, b'\x00\x20\x00\x20', offset, 4)
        elif self.version == 5:
            self.patchedData = replaceBufferAtIndex(self.patchedData, b'\x00\x20', offset, 2)
        else:
            raise Exception('UNIMPLEMENTED!')
        
    def patch_pk_verify_sha1(self) -> None:
        offset = self.find_pk_verify_sha1()

        if self.version in (3, 4):
            self.patchedData = replaceBufferAtIndex(self.patchedData, b'\x00\x20\x00\x20', offset, 4)
        elif self.version == 5:
            self.patchedData = replaceBufferAtIndex(self.patchedData, b'\x00\x20', offset, 2)
        else:
            raise Exception('UNIMPLEMENTED!')
