
from .patterns import Pattern
from .utils import hexStringToHexInt, joinPatterns

from binpatch.file import readBinaryFromPath
from binpatch.find import find


class Find(Pattern):
    versions = {
        '3.x': {
            '3.1.3': '1357.5.30~6'
        },
        '4.x': {
            '4.0': '1504.50.73~2',
            '4.0.1': '1504.50.73~2',
            '4.0.2': '1504.50.80~1',
            '4.1': '1504.55.33~10',
            '4.2.1': '1504.58.28~3',
            '4.3': '1735.46~2',
            '4.3.1': '1735.46~2',
            '4.3.2': '1735.46~10',
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

    def findPattern(self, pattern):
        return find(pattern, self.data)

    def findOffset(self, patterns):
        for pattern in patterns:
            instruction = self.convertBytesToInstruction(pattern)
            print(f'Looking for pattern: {instruction}')

        pattern = joinPatterns(patterns)[0]
        match = self.findPattern(pattern)
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

    def find_sandbox_mac_label_get(self):
        patterns = self.form_sandbox_mac_label_get()
        return self.findOffset(patterns)

    def find_sandbox_entitlement_container_required(self):
        patterns = self.form_sandbox_entitlement_container_required()
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

    def find_sandbox_profile(self):
        patterns = self.form_sandbox_profile()
        return self.findOffset(patterns)

    def find_seatbelt_profile(self):
        patterns = self.form_seatbelt_profile()
        return self.findOffset(patterns)

    def getVersion(self):
        pattern = b'root:xnu'
        pattern_len = len(pattern)

        offset = self.findPattern(pattern)
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
            'sandbox_mac_label_get': False,
            'sandbox_entitlement_container_required': False,
            'nor_signature': False,
            'nor_llb_1': False,
            'nor_llb_2': False,
            'nor_llb_3': False,
            'nor_llb_4': False,
            'nor_llb_5': False,
            'sandbox_profile': False,
            'seatbelt_profile': False
        }

        try:
            for base in self.versions:
                versions = self.versions[base]

                for version in versions:
                    if versions[version] == version_string:
                        self.version = version

                        if base == '3.x':
                            to_find['vm_map_enter'] = True
                            to_find['debug_enabled'] = True
                            to_find['amfi_memcmp'] = True
                            to_find['nor_signature'] = True
                            to_find['nor_llb_1'] = True
                            to_find['nor_llb_2'] = True
                            to_find['nor_llb_3'] = True
                            to_find['nor_llb_4'] = True
                            to_find['nor_llb_5'] = True

                        elif base == '4.x':
                            if self.version in ('4.3', '4.3.1'):
                                to_find['sandbox_profile'] = True

                            if self.version in ('4.1', '4.3', '4.3.1', '4.3.2', '4.3.3'):
                                to_find['vm_map_enter'] = True

                            if self.version == '4.0':
                                to_find['seatbelt_profile'] = True

                            to_find['debug_enabled'] = True
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
                            if version in ('6.1.3', '6.1.6'):
                                to_find['debug_enabled'] = True
                                to_find['amfi_trust_cache'] = True
                                to_find['sandbox_mac_label_get'] = True
                                to_find['sandbox_entitlement_container_required'] = True

                            to_find['vm_map_enter'] = True
                            to_find['tfp0'] = True
                            to_find['nor_llb_1'] = True
                            to_find['nor_llb_2'] = True

                        raise StopIteration

        # Make sure we are only patching once. Some versions have the same
        # kernel version string.

        except StopIteration:
            pass

        for patch in to_find:
            func_names = dir(self)

            for func in func_names:
                if func == f'find_{patch}':
                    if to_find[patch]:
                        print(f'[*] {patch}')

                        func = getattr(self, func)

                        to_find[patch] = func()

        return to_find
