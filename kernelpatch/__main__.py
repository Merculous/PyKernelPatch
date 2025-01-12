
from argparse import ArgumentParser
from time import perf_counter

from binpatch.io import readBytesFromPath, writeBytesToPath
from binpatch.types import FilesystemPath

from .patch import NORPatcher3, NORPatcher4, NORPatcher5, NORPatcher6


def main() -> None:
    parser = ArgumentParser()

    parser.add_argument('-i', nargs=1, type=FilesystemPath)
    parser.add_argument('-o', nargs=1, type=FilesystemPath)

    parser.add_argument('--ios', nargs=1, type=str)

    args = parser.parse_args()

    if not args.i and not args.o and not args.ios:
        return parser.print_help()

    inData = readBytesFromPath(args.i[0])

    start = perf_counter()

    version = int(args.ios[0].split('.')[0])

    if version == 3:
        patcher = NORPatcher3(inData)
    elif version == 4:
        patcher = NORPatcher4(inData)
    elif version == 5:
        patcher = NORPatcher5(inData)
    elif version == 6:
        patcher = NORPatcher6(inData)
    else:
        raise Exception(f'Unsupported version: {args.ios[0]}')

    patcher.patch_hwdinfo_prod()
    patcher.patch_hwdinfo_ecid()
    patcher.patch_image3_validate_check()
    patcher.patch_hwdinfo_check()
    patcher.patch_shsh_encrypt()
    patcher.patch_pk_verify_sha1()

    end = perf_counter() - start

    print(f'Duration: {end:.6f}')

    outData = patcher.data

    writeBytesToPath(args.o[0], outData)


if __name__ == '__main__':
    main()
