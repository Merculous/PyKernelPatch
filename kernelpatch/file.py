
import json


def readBinaryFile(path):
    with open(path, 'rb') as f:
        return f.read()


def writeBinaryFile(path, data):
    with open(path, 'wb') as f:
        f.write(data)


def readJSONFile(path):
    with open(path) as f:
        return json.load(f)


def writeJSONFile(path, data, indent=2):
    with open(path, 'w') as f:
        json.dump(data, f, indent=indent)


def readTextFile(path):
    with open(path) as f:
        return f.readlines()
