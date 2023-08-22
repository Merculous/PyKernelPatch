
from .patterns import Pattern
from .utils import convertHexToBytes, formatBytes


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
                    found = hex(i-4)
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

    # TODO
    # Make this less ugly

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

        version_string = None
        version_string_offset = None

        for version in possible:
            version_string1 = search + b' ' + version

            match1 = self.findPattern(version_string1)

            if match1:
                version_string = version_string1
                version_string_offset = match1
                break

            for day in days:
                version_string2 = search + b' ' + version + b': ' + day[:1]

                match2 = self.findPattern(version_string2)

                version_string3 = search + b' ' + version + b': ' + day[:2]

                match3 = self.findPattern(version_string3)

                if match2:
                    version_string = version_string2
                    version_string_offset = match2
                    break

                elif match3:
                    version_string = version_string3
                    version_string_offset = match3
                    break

        if not version_string:
            raise Exception('Could not find kernel version string!')

        # Need to check that the buffer doesn't contain garbage data

        extra = len(version_string) + 75

        i = int(version_string_offset[2:], 16)

        buffer_end = i + extra

        buffer = self.data[i:buffer_end]

        buffer_hex = formatBytes(buffer)

        version_string_hex = formatBytes(version_string)
        version_string_index = buffer_hex.index(version_string_hex)

        new_buffer_hex = buffer_hex[version_string_index:]

        if not new_buffer_hex.startswith(version_string_hex):
            raise Exception('Buffer does not start with kernel version string!')

        new_i_hex = hex(buffer_end + 8)
        new_i = int(new_i_hex[2:], 16)

        start = i + version_string_index // 2
        start_hex = hex(start)

        new_buffer = self.data[start:new_i]
        new_buffer_hex = formatBytes(new_buffer)

        new_buffer_X_index = new_buffer_hex.index('58')

        new_buffer_hex = new_buffer_hex[:new_buffer_X_index+2]
        new_buffer_hex_end = new_buffer_hex[new_buffer_X_index:]

        new_buffer = convertHexToBytes(new_buffer_hex)
        new_buffer_len = len(new_buffer)

        if new_buffer_hex_end != '58':
            raise Exception(f'Failed extracting kernel version. Got buffer: {buffer}')

        kernel_version = new_buffer.split(b';')[1].split(b'-')[1].split(b'/')[0].decode('utf-8')

        results = (
            hex(new_buffer_len),
            start_hex,
            hex(start + new_buffer_len),
            new_buffer,
            kernel_version
        )

        print(f'Found kernel version string: {results[3].decode("utf-8")}')

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

        offsets = sorted([int(o[2:], 16) for o in offsets])

        offsets = [hex(o) for o in offsets]

        for offset_sorted in offsets:
            for name in info:
                for offset in info[name]:
                    if offset == offset_sorted:
                        new = (offset_sorted, name, info[name][offset_sorted])
                        new_info.append(new)

        return new_info

    def findOffsets(self):
        version_string = self.find_KernelVersion()

        for major in self.kernel_versions:
            for version in self.kernel_versions[major]:
                if version_string[-1] == self.kernel_versions[major][version]:
                    break

        self.initPatternObj(version)

        offsets = (
            self.find_CSEnforcement(),
            self.find_AMFIMemcmp(),
            self.find_SignatureCheck(),
            self.find_Vm_map_enter(),
            self.find_Tfp0(),
            self.find_AMFIHook(),
            self.find_AppleImage3NORAccess(),
            self.find_PE_i_can_has_debugger()
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
