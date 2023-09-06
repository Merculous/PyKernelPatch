
from .patterns import Pattern
from .utils import formatBytes, hexStringToHexInt


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

    def findPattern(self, pattern, print_hex=False):
        data_len = len(self.data)
        pattern_len = len(pattern)

        if not print_hex:
            print(f'Looking for pattern: {pattern}')
        else:
            print(f'Looking for pattern: {formatBytes(pattern)}')

        for i in range(0, data_len, pattern_len):
            buffer = self.data[i:i+pattern_len]

            i_hex = hex(i)

            if pattern == buffer:
                print(f'Found pattern at offset: {i_hex}')
                return i_hex

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
            while not found_string:
                version_string1 = search + b' ' + version

                match1 = self.findPattern(version_string1)

                if match1:
                    found_string = version_string1
                    found_string_offset = match1
                    break

                for day in days:
                    version_string2 = search + b' ' + version + b': ' + day[:1]

                    match2 = self.findPattern(version_string2)

                    if match2:
                        found_string = version_string2
                        found_string_offset = match2
                        break

                    version_string3 = search + b' ' + version + b': ' + day[:2]

                    match3 = self.findPattern(version_string3)

                    if match3:
                        found_string = version_string3
                        found_string_offset = match3
                        break

                break

        if not found_string:
            raise Exception('Could not find kernel version string!')

        string_offset_int = hexStringToHexInt(found_string_offset)

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

    def versionStringToVersion(self, results):
        versions = self.kernel_versions

        for base in versions:
            for version in versions[base]:
                if versions[base][version] == results[1]:
                    return version

    def findOffsets(self, patterns, print_hex=False):
        offsets = []

        for pattern in patterns:
            offset = self.findPattern(pattern, print_hex)

            if offset:
                offsets.append((offset, pattern))

        if offsets:
            return tuple(offsets)
        else:
            return None

    def crunchPatternUntilTrue(self, pattern, control):
        pattern_len = len(pattern)

        matches = []

        # Look for the pattern

        result = self.findPattern(pattern)

        if result:
            matches.append((result, formatBytes(pattern)))
            result = None

            # We found a match.
            # Crunch anyway just in case we manage to find
            # a match that's smaller than the original.
            # This is just so we can shorten the pattern,
            # if possible.

        # Search left -> Right
        # Remove 1 byte from the front

        if not result:
            for i in range(1, pattern_len):
                buffer = pattern[i:]

                result = self.findPattern(buffer, True)

                if result:
                    matches.append((result, formatBytes(buffer)))
                    result = None

                if buffer[:2] == control:
                    # We need the control in the buffer
                    # We shortened as much as possible

                    print('Hit control! Breaking...')
                    break

        if not result:
            for i in range(1, pattern_len):
                buffer = pattern[:-i]

                result = self.findPattern(buffer, True)

                if result:
                    matches.append((result, formatBytes(buffer)))
                    result = None

                if buffer[-2:] == control:
                    # We need the control in the buffer
                    # We shortened as much as possible

                    print('Hit control! Breaking...')
                    break

        if not result:
            for i in range(1, pattern_len):
                buffer = pattern[i:-i]

                result = self.findPattern(buffer, True)

                if result:
                    matches.append((result, formatBytes(buffer)))
                    result = None

                if buffer[:2] == control or buffer[-2:] == control:
                    # We need the control in the buffer
                    # We shortened as much as possible

                    print('Hit control! Breaking...')
                    break

        if matches:
            return tuple(matches)
        else:
            return None

    def find_CSEnforcement(self):
        patterns = self.pattern_obj.form_CSEnforcement()
        return self.findOffsets(patterns)

    def find_AMFIMemcmp(self):
        patterns = self.pattern_obj.form_AMFIMemcmp()
        return self.findOffsets(patterns)

    def find_AppleImage3NORAccess(self):
        patterns = self.pattern_obj.form_AppleImage3NORAccess()
        return self.findOffsets(patterns)

    def find_signatureCheck(self):
        patterns = self.pattern_obj.form_signatureCheck()
        return self.findOffsets(patterns)

    def findAllOffsets(self):
        version_string = self.find_KernelVersion()

        version = self.versionStringToVersion(version_string)

        self.pattern_obj = Pattern(version)

        info = {
            'cs_enforcement': self.find_CSEnforcement(),
            'amfi_memcmp': self.find_AMFIMemcmp(),
            'apple_image3_nor_access': self.find_AppleImage3NORAccess(),
            'sig_check': self.find_signatureCheck()
        }

        return info
