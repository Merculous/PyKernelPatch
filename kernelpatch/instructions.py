
from capstone import Cs


class Instructions(Cs):
    def __init__(self, arch, mode):
        super().__init__(arch, mode)

    def hexToInstruction(self, data, offset):
        fields = self.disasm_lite(data, offset)
        keys = ('address', 'size', 'mnemonic', 'op_str')
        instructions = {k: v for k, v in zip(keys, next(fields))}
        return instructions
