
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
            '6.0.1': '2107.2.34~2',
            '6.1': '2107.7.55~11',
            '6.1.2': '2107.7.55~11',
            '6.1.3': '2107.7.55.2.2~1',
            '6.1.6': '2107.7.55.2.2~1'
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

    def findOffset(self, patterns):
        for pattern in patterns:
            instruction = self.convertBytesToInstruction(pattern)
            print(f'Looking for pattern: {instruction}')

        pattern = joinPatterns(patterns)[0]
        match = self.find(pattern)
        return (match, pattern)

    def find_debug_enabled(self):
        patterns = self.form_debug_enabled()
        return self.findOffset(patterns)

    def find_vm_map_enter(self):
        patterns = self.form_vm_map_enter()
        return self.findOffset(patterns)

    def find_tfp0(self):
        patterns = self.form_tfp0()
        return self.findOffset(patterns)

    def find_amfi_memcmp(self):
        patterns = self.form_amfi_memcmp()
        return self.findOffset(patterns)

    def find_amfi_trust_cache(self):
        patterns = self.form_amfi_trust_cache()
        return self.findOffset(patterns)

    def find_nor_signature(self):
        patterns = self.form_nor_signature()
        return self.findOffset(patterns)

    def find_nor_llb_1(self):
        patterns = self.form_nor_llb_1()
        return self.findOffset(patterns)

    def find_nor_llb_2(self):
        patterns = self.form_nor_llb_2()
        return self.findOffset(patterns)

    def find_nor_llb_3(self):
        patterns = self.form_nor_llb_3()
        return self.findOffset(patterns)

    def find_nor_llb_4(self):
        patterns = self.form_nor_llb_4()
        return self.findOffset(patterns)

    def find_nor_llb_5(self):
        patterns = self.form_nor_llb_5()
        return self.findOffset(patterns)

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
            'tfp0': False,
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
                    self.version = version

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

                    elif base == '5.x':
                        to_find['debug_enabled'] = True,
                        to_find['amfi_memcmp'] = True
                        to_find['nor_llb_1'] = True
                        to_find['nor_llb_2'] = True
                        to_find['nor_llb_3'] = True
                        to_find['nor_llb_4'] = True
                        to_find['nor_llb_5'] = True
                        to_find['nor_signature'] = True

                    elif base == '6.x':
                        to_find['vm_map_enter'] = True
                        to_find['tfp0'] = True
                        to_find['nor_llb_1'] = True
                        to_find['nor_llb_2'] = True

        for patch in to_find:
            func_names = dir(self)

            for func in func_names:
                if func == f'find_{patch}':
                    if to_find[patch]:
                        print(f'[*] {patch}')

                        func = getattr(self, func)

                        to_find[patch] = func()

        return to_find
