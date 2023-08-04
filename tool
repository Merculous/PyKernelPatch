#!/usr/bin/env python3

import ctypes
import subprocess
from argparse import ArgumentParser

from macholib.MachO import MachO


def loadObject(path):
    object = ctypes.cdll.LoadLibrary(path)
    return object


def listFunctions(path):
    subprocess.run(('nm', '-D', path))


def main():
    parser = ArgumentParser()

    parser.add_argument('--object', nargs=1)
    parser.add_argument('--list', action='store_true')
    parser.add_argument('--test', nargs=1)

    args = parser.parse_args()

    if args.list and args.object:
        listFunctions(args.object[0])
    elif args.test:
        macho = MachO(args.test[0])
        macho_headers = macho.headers[0]
        macho_commands = macho_headers.commands

        for command in macho_commands:
            for thing in command:
                print(thing)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
