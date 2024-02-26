
import json
from typing import Any


def readBinaryFromPath(path: str) -> bytes:
    with open(path, 'rb') as f:
        data = f.read()
        return data


def writeBinaryToPath(path: str, data: bytes) -> None:
    with open(path, 'wb') as f:
        f.write(data)


def readJSONFromPath(path: str) -> Any:
    with open(path) as f:
        data = json.load(f)
        return data


def writeJSONToPath(path: str, data: Any, indent: int = 2) -> None:
    with open(path, 'w') as f:
        json.dump(data, f, indent=indent)
