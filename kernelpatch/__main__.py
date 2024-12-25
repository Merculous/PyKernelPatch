
from argparse import ArgumentParser
from time import perf_counter

from binpatch.io import readBytesFromPath
from binpatch.types import FilesystemPath

from .find import AppleImage3NORAccess


def main() -> None:
    parser = ArgumentParser()

    parser.add_argument('-i', nargs=1, type=FilesystemPath)
    parser.add_argument('-o', nargs=1, type=FilesystemPath)

    args = parser.parse_args()

    if not args.i and not args.o:
        parser.print_help()

    inData = readBytesFromPath(args.i[0])

    startTime = perf_counter()

    a = AppleImage3NORAccess(inData)
    a.find_hwdinfo_prod()
    a.find_hwdinfo_ecid()
    a.find_image3_validate()
    a.find_hwdinfo_func()
    a.find_shsh_encrypt()
    a.find_pk_verify_SHA1()

    endTime = perf_counter() - startTime

    print(f'{endTime:.6f}')


if __name__ == '__main__':
    main()
