
from argparse import ArgumentParser
from time import perf_counter

from binpatch.io import readBytesFromPath, writeBytesToPath
from binpatch.types import FilesystemPath

from .patch import AppleImage3NORAccessPatcher


def main() -> None:
    parser = ArgumentParser()

    parser.add_argument('-i', nargs=1, type=FilesystemPath)
    parser.add_argument('-o', nargs=1, type=FilesystemPath)

    parser.add_argument('--ios', nargs=1, type=str)

    args = parser.parse_args()

    if not args.i and not args.o:
        return parser.print_help()

    inData = readBytesFromPath(args.i[0])
    version = int(args.ios[0].split('.')[0]) if '.' in args.ios[0] else int(args.ios[0])

    startTime = perf_counter()

    patcher = AppleImage3NORAccessPatcher(inData, version)

    if version in (3, 4, 5):
        patcher.patch_hwdinfo_prod()
        patcher.patch_hwdinfo_ecid()
        patcher.patch_validate_check()
        patcher.patch_hwdinfo_check()
        patcher.patch_shsh_encrypt()
        patcher.patch_pk_verify_sha1()

    elif version == 6:
        patcher.patch_validate_check()
        patcher.patch_hwdinfo_check()

    else:
        print(f'iOS {version} not supported yet!')

    endTime = perf_counter() - startTime

    print(f'Duration: {endTime:.6f}')

    writeBytesToPath(args.o[0], patcher.patchedData)


if __name__ == '__main__':
    main()
