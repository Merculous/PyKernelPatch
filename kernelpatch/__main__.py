
from argparse import ArgumentParser

from .file import readBinaryFromPath, writeBinaryToPath
from .patcher import Patcher


def main() -> None:
    parser = ArgumentParser()

    parser.add_argument('-i', metavar='input file', nargs=1)
    parser.add_argument('-o', metavar='output file', nargs=1)

    args = parser.parse_args()

    input_data = None
    output_data = None

    if args.i:
        input_data = readBinaryFromPath(args.i[0])

        patcher = Patcher(input_data)
        patcher.allowFlashingUnsignedImg3ToNOR()

        output_data = patcher.data

        writeBinaryToPath(args.o[0], output_data)

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
