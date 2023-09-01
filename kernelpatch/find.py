
from .patterns import Pattern
from .utils import convertHexToBytes, formatBytes, hexOffsetToHexInt


class Find:
    kernel_versions = {
        '5.x': {
            '5.0': '1878.4.43~2',
            '5.0.1': '1878.4.46~1',
            '5.1': '1878.11.8~1',
            '5.1.1': '1878.11.10~1'
        }
    }

    def __init__(self, data):
        self.data = data

    def findPattern(self, pattern):
        data_len = len(self.data)
        pattern_len = len(pattern)

        found = None

        for i in range(0, data_len, pattern_len):
            look_back_buffer = self.data[i-4:i]

            buffer = self.data[i:i+pattern_len]

            look_ahead_buffer = self.data[i+pattern_len:i+pattern_len+4]

            window = look_back_buffer + buffer + look_ahead_buffer

            if pattern == buffer:
                found = hex(i)

            else:
                if pattern in window:
                    pattern_i = window.index(pattern)
                    found = hex(i-pattern_i)
                else:
                    window = b''

        return found

    def findPatchOffset(self, patterns):
        info = {}

        for pattern in patterns:
            offset = self.findPattern(pattern)

            if offset:
                match = {offset: pattern}

                info.update(match)

        return info

    def find_KernelVersion(self):
        search = b'Darwin Kernel Version'

        possible = (
            b'10.3.1',
            b'10.4.0',
            b'11.0.0',
            b'13.0.0',
            b'14.0.0',
            b'15.0.0',
            b'15.6.0',
            b'16.0.0',
            b'16.1.0',
            b'16.3.0',
            b'16.5.0',
            b'16.6.0',
            b'16.7.0'
        )

        days = (
            b'Mon',
            b'Tue',
            b'Wed',
            b'Thu',
            b'Fri',
            b'Sat',
            b'Sun'
        )

        found_string = None
        found_string_offset = None

        for version in possible:
            version_string1 = search + b' ' + version

            match1 = self.findPattern(version_string1)

            if match1:
                found_string = version_string1
                found_string_offset = match1
                break

            for day in days:
                version_string2 = search + b' ' + version + b': ' + day[:1]

                match2 = self.findPattern(version_string2)

                version_string3 = search + b' ' + version + b': ' + day[:2]

                match3 = self.findPattern(version_string3)

                if match2:
                    found_string = version_string2
                    found_string_offset = match2
                    break

                elif match3:
                    found_string = version_string3
                    found_string_offset = match3
                    break

        if not found_string:
            raise Exception('Could not find kernel version string!')

        string_offset_int = hexOffsetToHexInt(found_string_offset)

        extra = len(found_string) + 88

        search_buffer = self.data[string_offset_int-4:string_offset_int+extra]

        actual_string_i = search_buffer.index(found_string)

        x_string_i = search_buffer.index(b'X')

        buffer_cleaned = search_buffer[actual_string_i:x_string_i+1]

        search_buffer_offset = hex(self.data.index(buffer_cleaned))

        kernel_version = buffer_cleaned.split(b';')[1].split(b'-')[1].split(b'/')[0]

        results = (
            search_buffer_offset,
            kernel_version.decode(),
            buffer_cleaned.decode()
        )

        return results

    def initPatternObj(self, version):
        self.Pattern = Pattern(version)

    def find_CSEnforcement(self):
        search = self.Pattern.form_CSEnforcement()
        offsets = self.findPatchOffset(search)
        info = {'cs_enforcement': offsets}
        return info

    def find_AMFIMemcmp(self):
        search = self.Pattern.form_AMFIMemcmp()
        offsets = self.findPatchOffset(search)
        info = {'amfi_memcmp': offsets}
        return info

    def find_Vm_map_enter(self):
        search = self.Pattern.form_vm_map_enter()
        offsets = self.findPatchOffset(search)
        info = {'vm_map_enter': offsets}
        return info

    def find_Tfp0(self):
        search = self.Pattern.form_tfp0()
        offsets = self.findPatchOffset(search)
        info = {'tfp0': offsets}
        return info

    def find_PE_i_can_has_debugger(self):
        search = self.Pattern.form_PE_i_can_has_debugger()
        offsets = self.findPatchOffset(search)
        info = {'pe_i_can_has_debugger': offsets}
        return info

    def find_AMFIHook(self):
        search = self.Pattern.form_AMFIHook()
        offsets = self.findPatchOffset(search)
        info = {'amfi_hook': offsets}
        return info

    def find_SignatureCheck(self):
        search = self.Pattern.form_signatureCheck()
        offsets = self.findPatchOffset(search)
        info = {'sig_check': offsets}
        return info

    def find_AppleImage3NORAccess(self):
        search = self.Pattern.form_AppleImage3NORAccess()
        offsets = self.findPatchOffset(search)
        info = {'apple_image3_nor_access': offsets}
        return info

    def cleanupOffsets(self, info):
        new_info = []

        offsets = []

        for name in info:
            for offset in info[name]:
                offsets.append(offset)

        offsets = sorted([hexOffsetToHexInt(o) for o in offsets])

        offsets = [hex(o) for o in offsets]

        for offset_sorted in offsets:
            for name in info:
                for offset in info[name]:
                    if offset == offset_sorted:
                        new = (offset_sorted, name, info[name][offset_sorted])
                        new_info.append(new)

        return new_info

    def findOffsets(self):
        kernel_version = self.find_KernelVersion()

        print(f'Found kernel version string at offset: {kernel_version[0]}')

        for major in self.kernel_versions:
            for version in self.kernel_versions[major]:
                if kernel_version == self.kernel_versions[major][version]:
                    break

        self.initPatternObj(version)

        offsets = (
            self.find_CSEnforcement(),
            self.find_AMFIMemcmp(),
            self.find_SignatureCheck(),
            self.find_AppleImage3NORAccess()
        )

        info = {}

        for part in offsets:
            if part:
                info.update(part)

        if not info:
            raise Exception('No offsets were found!')

        info_sorted = self.cleanupOffsets(info)

        for match in info_sorted:
            print(f'Found {match[1]} at offset {match[0]}')

        return info_sorted
