
from binascii import hexlify
from struct import unpack
from typing import List, NamedTuple


def unpackToDictWithKeys(format_str: str, data: bytes, dst: NamedTuple) -> dict:
    fields = unpack(format_str, data)
    dst_dict = dst._make(fields)._asdict()
    return dst_dict


# I'm sure there's a better way to do this,
# but whatever...

def getAllNullTerminatedStrings(data: bytes) -> List[bytes]:
    NULL_CHAR = b'\x00'

    strings = []

    string = b''

    for i in range(len(data)):
        char = data[i:i+1]

        if char == NULL_CHAR:
            if not string:
                continue

            strings.append(string)
            string = b''
            continue

        string += char

    return strings


def formatIOKitPlistData(data: list) -> dict | list | str:
    # This is from ChatGPT cause I'm lazy

    if isinstance(data, dict):
        # If it's a dictionary, recursively convert values
        return {key: formatIOKitPlistData(value) for key, value in data.items()}
    elif isinstance(data, list):
        # If it's a list, recursively convert elements
        return [formatIOKitPlistData(item) for item in data]
    elif isinstance(data, bytes):
        # If it's a byte object, convert to hex string
        return hexlify(data).decode('utf-8')
    else:
        # Otherwise, return the data as it is
        return data
