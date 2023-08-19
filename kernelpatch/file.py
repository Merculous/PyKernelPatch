
def readBinaryFile(path):
    with open(path, 'rb') as f:
        return f.read()


def writeBinaryFile(data, path):
    with open(path, 'wb') as f:
        f.write(data)
