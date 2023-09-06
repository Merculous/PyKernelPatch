
import binascii


def convertHexToBytes(data):
    return bytes.fromhex(data)


def formatBytes(data):
    return binascii.hexlify(data).decode()


def joinPatterns(*data):
    return tuple([b''.join(p) for p in data if p])


def hexStringToHexInt(data):
    return int(data, 16)


def readIDAAssembly(lines):
    split = [l.split()[1:] for l in lines]

    new = []

    for line in split:
        values = []

        for value in line:
            if value == ';':
                break

            if len(value) == 2:
                try:
                    hexStringToHexInt(value)
                except ValueError:
                    pass
                else:
                    values.append(value.lower())

        if values:
            new.append(' '.join(values))

    return tuple(new)
