
from argparse import ArgumentParser

from .config import ARCH, MODE
from .file import readTextFile, writeBinaryFile
from .patch import Patch
from .utils import readIDAAssembly


def main():
    parser = ArgumentParser()

    parser.add_argument('--orig', nargs=1)
    parser.add_argument('--patched', nargs=1)
    parser.add_argument('--convert', nargs=1)
    parser.add_argument('--diff', action='store_true')
    parser.add_argument('--patch', action='store_true')

    parser.add_argument('--test', action='store_true')

    args = parser.parse_args()

    if args.diff:
        if args.orig and args.patched:
            pass

    elif args.patch:
        if args.orig and args.patched:
            patch = Patch(ARCH, MODE, args.orig[0])
            data = patch.patch()
            writeBinaryFile(args.patched[0], data)

    elif args.convert:
        lines = readTextFile(args.convert[0])
        stuff = readIDAAssembly(lines)

        for line in stuff:
            print(line)

    else:
        parser.print_help()


main()
