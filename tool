#!/usr/bin/env python3

import ctypes
import subprocess
from argparse import ArgumentParser


def loadObject(path):
    object = ctypes.cdll.LoadLibrary(path)
    return object


def listFunctions(path):
    subprocess.run(('nm', '-D', path))


def main():
    parser = ArgumentParser()

    parser.add_argument('--object', nargs=1)
    parser.add_argument('--list', action='store_true')

    args = parser.parse_args()

    if args.list and args.object:
        listFunctions(args.object[0])
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
