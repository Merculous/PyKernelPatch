
import json

from .utils import formatBytes


def writeJSON(data, path):
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)


def writeOffsetsToJSON(offsets, path):
    offsets_formatted = offsets.copy()

    for offset in offsets:
        for k, v in offsets[offset].items():
            offsets_formatted[offset][k] = formatBytes(v)

    writeJSON(offsets_formatted, path)
