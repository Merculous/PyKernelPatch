
import binascii


def convertHexToBytes(data):
    return bytes.fromhex(data)


def formatBytes(data):
    return binascii.hexlify(data).decode()


def joinPatterns(*data):
    return tuple([b''.join(p) for p in data if p])


def hexStringToHexInt(data):
    return int(data, 16)
