
from .patterns import Pattern
from .utils import hexStringToHexInt, joinPatterns

from binpatch.file import readBinaryFromPath


class Find(Pattern):
    versions = {
        '4.x': {
            '4.3.3': '1735.46~10'
        },
        '5.x': {
            '5.0': '1878.4.43~2',
            '5.0.1': '1878.4.46~1',
            '5.1': '1878.11.8~1',
            '5.1.1': '1878.11.10~1'
        },
        '6.x': {
            '6.0': '2107.2.33~4',
            '6.1': '2107.7.55~11',
            '6.1.3': '2107.7.55.2.2~1'
        }
    }

    def __init__(self, arch, mode, path):
        super().__init__(arch, mode)

        self.path = path
        self.data = readBinaryFromPath(self.path)

    def find(self, pattern):
        pattern_len = len(pattern)
        data_len = len(self.data)

        # KPM Algorithm
        # Code is based ("copied") off of this video
        # https://www.youtube.com/watch?v=JoF0Z7nVSrA

        lps = [0] * pattern_len

        prevLPS, i = 0, 1

        # Setup LPS to determine prefix/suffix matches

        while i < pattern_len:
            # Values match

            if pattern[i] == pattern[prevLPS]:
                lps[i] = prevLPS + 1
                prevLPS += 1
                i += 1

            # Values differ

            elif prevLPS == 0:
                lps[i] = 0
                i += 1

            else:
                # print(lps)
                prevLPS = lps[prevLPS - 1]

        # Search through the data

        i, j = 0, 0

        while i < data_len:
            if self.data[i] == pattern[j]:
                # Values matched

                i, j = i + 1, j + 1

            else:
                if j == 0:
                    # Values differ

                    i += 1
                else:
                    j = lps[j - 1]

            if j == pattern_len:
                offset = hex(i - pattern_len)
                print(f'Found pattern at offset: {offset}')
                return offset

        print('Did not find pattern!')
        return None

    def find_debug_enabled(self):
        patterns = self.form_debug_enabled()

        print('debug_enabled')

        pattern = joinPatterns(patterns)[0]

        match = self.find(pattern)

        return (match, pattern)

    def find_vm_map_enter(self):
        patterns = self.form_vm_map_enter()

        print('vm_map_enter')

        for pattern in patterns:
            instruction = self.convertBytesToInstruction(pattern)
            print(f'Looking for pattern: {instruction}')

        pattern = joinPatterns(patterns)[0]

        match = self.find(pattern)

        return (match, pattern)

    def find_amfi_memcmp(self):
        patterns = self.form_amfi_memcmp()

        print('amfi_memcmp')

        for pattern in patterns:
            instruction = self.convertBytesToInstruction(pattern)
            print(f'Looking for pattern: {instruction}')

        pattern = joinPatterns(patterns)[0]

        match = self.find(pattern)

        return (match, pattern)

    def find_amfi_trust_cache(self):
        patterns = self.form_amfi_trust_cache()

        print('amfi_signature')

        for pattern in patterns:
            instruction = self.convertBytesToInstruction(pattern)
            print(f'Looking for pattern: {instruction}')

        pattern = joinPatterns(patterns)[0]

        match = self.find(pattern)

        return (match, pattern)

    def find_nor_signature(self):
        patterns = self.form_nor_signature()

        print('nor_signature')

        for pattern in patterns:
            instruction = self.convertBytesToInstruction(pattern)
            print(f'Looking for pattern: {instruction}')

        pattern = joinPatterns(patterns)[0]

        match = self.find(pattern)

        return (match, pattern)

    def find_nor_llb_1(self):
        patterns = self.form_nor_llb_1()

        print('nor_llb_1')

        for pattern in patterns:
            instruction = self.convertBytesToInstruction(pattern)
            print(f'Looking for pattern: {instruction}')

        pattern = joinPatterns(patterns)[0]

        match = self.find(pattern)

        return (match, pattern)

    def find_nor_llb_2(self):
        patterns = self.form_nor_llb_2()

        print('nor_llb_2')

        for pattern in patterns:
            instruction = self.convertBytesToInstruction(pattern)
            print(f'Looking for pattern: {instruction}')

        pattern = joinPatterns(patterns)[0]

        match = self.find(pattern)

        return (match, pattern)

    def find_nor_llb_3(self):
        patterns = self.form_nor_llb_3()

        print('nor_llb_3')

        for pattern in patterns:
            instruction = self.convertBytesToInstruction(pattern)
            print(f'Looking for pattern: {instruction}')

        pattern = joinPatterns(patterns)[0]

        match = self.find(pattern)

        return (match, pattern)

    def find_nor_llb_4(self):
        patterns = self.form_nor_llb_4()

        print('nor_llb_4')

        for pattern in patterns:
            instruction = self.convertBytesToInstruction(pattern)
            print(f'Looking for pattern: {instruction}')

        pattern = joinPatterns(patterns)[0]

        match = self.find(pattern)

        return (match, pattern)

    def find_nor_llb_5(self):
        patterns = self.form_nor_llb_5()

        print('nor_llb_5')

        for pattern in patterns:
            instruction = self.convertBytesToInstruction(pattern)
            print(f'Looking for pattern: {instruction}')

        pattern = joinPatterns(patterns)[0]

        match = self.find(pattern)

        return (match, pattern)

    def getVersion(self):
        pattern = b'root:xnu'
        pattern_len = len(pattern)

        offset = self.find(pattern)
        offset = hexStringToHexInt(offset)

        buffer = self.data[offset:offset+pattern_len+25]

        version = buffer.split(b'-')[1].split(b'/')[0].decode()
        return version

    def findAllOffsets(self):
        version_string = self.getVersion()

        to_find = {
            'debug_enabled': False,
            'vm_map_enter': False,
            'amfi_memcmp': False,
            'amfi_trust_cache': False,
            'nor_signature': False,
            'nor_llb_1': False,
            'nor_llb_2': False,
            'nor_llb_3': False,
            'nor_llb_4': False,
            'nor_llb_5': False
        }

        for base in self.versions:
            versions = self.versions[base]

            for version in versions:
                if versions[version] == version_string:
                    if base == '4.x':
                        to_find['debug_enabled'] = True
                        to_find['vm_map_enter'] = True
                        to_find['amfi_memcmp'] = True
                        to_find['amfi_trust_cache'] = True
                        to_find['nor_signature'] = True
                        to_find['nor_llb_1'] = True
                        to_find['nor_llb_2'] = True
                        to_find['nor_llb_3'] = True
                        to_find['nor_llb_4'] = True
                        to_find['nor_llb_5'] = True

        if to_find['debug_enabled']:
            to_find['debug_enabled'] = self.find_debug_enabled()

        if to_find['vm_map_enter']:
            to_find['vm_map_enter'] = self.find_vm_map_enter()

        if to_find['amfi_memcmp']:
            to_find['amfi_memcmp'] = self.find_amfi_memcmp()

        if to_find['amfi_trust_cache']:
            to_find['amfi_trust_cache'] = self.find_amfi_trust_cache()

        if to_find['nor_signature']:
            to_find['nor_signature'] = self.find_nor_signature()

        if to_find['nor_llb_1']:
            to_find['nor_llb_1'] = self.find_nor_llb_1()

        if to_find['nor_llb_2']:
            to_find['nor_llb_2'] = self.find_nor_llb_2()

        if to_find['nor_llb_3']:
            to_find['nor_llb_3'] = self.find_nor_llb_3()

        if to_find['nor_llb_4']:
            to_find['nor_llb_4'] = self.find_nor_llb_4()

        if to_find['nor_llb_5']:
            to_find['nor_llb_5'] = self.find_nor_llb_5()

        return to_find
