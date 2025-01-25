
from binpatch.types import Buffer, Index
from binpatch.utils import getBufferAtIndex


def getNullTerminatedStringAtIndex(data: Buffer, index: Index) -> str:
    dataSize = len(data)
    nullTermStr = bytearray()

    for i in range(index, dataSize):
        char = data[i]

        if char == 0:
            break

        nullTermStr.append(char)

    return nullTermStr.decode()
