
from argparse import ArgumentParser

from binpatch.io import readBytesFromPath, writeBytesToPath
from binpatch.types import FilesystemPath

from .patch import NORPatcher3


def main() -> None:
    parser = ArgumentParser()

    parser.add_argument('-i', nargs=1, type=FilesystemPath)
    parser.add_argument('-o', nargs=1, type=FilesystemPath)

    args = parser.parse_args()

    if not args.i and not args.o:
        return parser.print_help()

    inData = readBytesFromPath(args.i[0])

    patcher = NORPatcher3(inData)
    patcher.patch_hwdinfo_prod()
    patcher.patch_hwdinfo_ecid()
    patcher.patch_image3_validate_check()
    patcher.patch_hwdinfo_check()
    patcher.patch_shsh_encrypt()
    patcher.patch_pk_verify_sha1()

    outData = patcher.data

    writeBytesToPath(args.o[0], outData)


if __name__ == '__main__':
    main()
