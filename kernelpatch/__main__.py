
from argparse import ArgumentParser

from .diff import diffKernels
from .file import readBinaryFile, writeBinaryFile, writeJSONFile
from .patch import Patch


def main():
    parser = ArgumentParser()

    parser.add_argument('--orig', nargs=1)
    parser.add_argument('--patched', nargs=1)
    parser.add_argument('--diff', action='store_true')
    parser.add_argument('--patch', action='store_true')

    args = parser.parse_args()

    if args.diff:
        if args.orig and args.patched:
            diff = diffKernels(args.orig[0], args.patched[0])
            writeJSONFile('diff.json', diff)

    elif args.patch:
        if args.orig and args.patched:
            data = readBinaryFile(args.orig[0])
            patched_data = Patch(data).patchKernel()
            writeBinaryFile(args.patched[0], patched_data)

    else:
        parser.print_help()


main()
