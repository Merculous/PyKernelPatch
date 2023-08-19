
from argparse import ArgumentParser

from .diff import diffKernels
from .find import findOffsets
from .json import writeJSON, writeOffsetsToJSON
from .patch import patchKernel


def main():
    parser = ArgumentParser()

    parser.add_argument('--orig', nargs=1)
    parser.add_argument('--patched', nargs=1)
    parser.add_argument('--find', action='store_true')
    parser.add_argument('--diff', action='store_true')
    parser.add_argument('--patch', action='store_true')

    args = parser.parse_args()

    if args.find:
        if args.orig and not args.patched:
            offsets = findOffsets(args.orig[0])
            writeOffsetsToJSON(offsets, 'offsets.json')

    elif args.diff:
        if args.orig and args.patched:
            diff = diffKernels(args.orig[0], args.patched[0])
            writeJSON(diff, 'diff.json')

    elif args.patch:
        if args.orig and args.patched:
            patchKernel(args.orig[0], args.patched[0])

    else:
        parser.print_help()


main()
