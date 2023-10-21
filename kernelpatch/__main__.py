
from argparse import ArgumentParser

from .config import ARCH, MODE
from .patch import Patch

from binpatch.file import writeBinaryToPath


def main():
    parser = ArgumentParser()

    parser.add_argument('--orig', nargs=1)
    parser.add_argument('--patched', nargs=1)

    args = parser.parse_args()

    if args.orig and args.patched:
        patch = Patch(ARCH, MODE, args.orig[0])
        data = patch.patch()
        writeBinaryToPath(args.patched[0], data)

    else:
        parser.print_help()


main()
