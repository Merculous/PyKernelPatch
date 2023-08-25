
import binascii


def convertHexToBytes(data):
    return bytes.fromhex(data)


def formatBytes(data):
    return binascii.hexlify(data).decode('utf-8')


def joinPatterns(*data):
    return tuple([b''.join(p) for p in data])
