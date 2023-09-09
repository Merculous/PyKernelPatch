
from .patterns import Pattern
from .utils import formatBytes, hexStringToHexInt


class Find:
    kernel_versions = {
        '5.x': {
            '5.0': '1878.4.43~2',
            '5.0.1': '1878.4.46~1',
            '5.1': '1878.11.8~1',
            '5.1.1': '1878.11.10~1'
        },
        '6.x': {
            '6.0': '2107.2.33~4',
            '6.1.3': '2107.7.55.2.2~1'
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
        xnu_string = b'root:xnu'
        xnu_string_len = len(xnu_string)

        match = self.findPattern(xnu_string)

        xnu_version = None

        if not match:
            darwin = b'Darwin Kernel Ve'
            darwin_len = len(darwin)

            match = self.findPattern(darwin)

            if match:
                offset = hexStringToHexInt(match)

                buffer = self.data[offset:offset+darwin_len+90]

                buffer_end = buffer.index(b'X') + 1

                buffer = buffer[:buffer_end]

                xnu_version = buffer.split(xnu_string + b'-')[1].split(b'/')[0].decode()

        else:
            offset = hexStringToHexInt(match)

            buffer = self.data[offset:offset+xnu_string_len+20]

            xnu_version = buffer.decode().split('/')[0].split(f'{xnu_string.decode()}-')[1]

        if not match:
            raise Exception('Could not find kernel version string!')

        return xnu_version

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

                while control in buffer:
                    result = self.findPattern(buffer, True)

                    if result:
                        matches.append((result, formatBytes(buffer)))
                        result = None

                    break
                else:
                    break

        if not result:
            for i in range(1, pattern_len):
                buffer = pattern[:-i]

                result = self.findPattern(buffer, True)

                while control in buffer:
                    result = self.findPattern(buffer, True)

                    if result:
                        matches.append((result, formatBytes(buffer)))
                        result = None

                    break
                else:
                    break

        if not result:
            for i in range(1, pattern_len):
                buffer = pattern[i:-i]

                result = self.findPattern(buffer, True)

                while control in buffer:
                    result = self.findPattern(buffer, True)

                    if result:
                        matches.append((result, formatBytes(buffer)))
                        result = None

                    break
                else:
                    break

        if matches:
            return tuple(matches)
        else:
            return None

    def find_CSEnforcement(self):
        patterns = self.pattern_obj.form_CSEnforcement()
        return self.findOffsets(patterns)

    def find_vm_map_enter(self):
        patterns = self.pattern_obj.form_vm_map_enter()
        return self.findOffsets(patterns)

    def find_tfp0(self):
        patterns = self.pattern_obj.form_tfp0()
        return self.findOffsets(patterns)

    def find_AMFICertification(self):
        patterns = self.pattern_obj.form_AMFICertification()
        return self.findOffsets(patterns)

    def find_Sandbox(self):
        patterns = self.pattern_obj.form_Sandbox()
        return self.findOffsets(patterns)

    def find_SandboxEntitlement(self):
        patterns = self.pattern_obj.form_SandboxEntitlement()
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

        to_find = {
            'cs_enforcement': False,
            'vm_map_enter': False,
            'tfp0': False,
            'amfi_certification': False,
            'sandbox': False,
            'sandbox_entitlement': False,
            'amfi_memcmp': False,
            'apple_image3_nor_access': False,
            'signature_check': False
        }

        xnu_version = None

        for base in self.kernel_versions:
            versions = self.kernel_versions[base]

            for version in versions:
                if versions[version] == version_string:
                    xnu_version = version

                    if base == '5.x':
                        to_find['cs_enforcement'] = True
                        to_find['amfi_memcmp'] = True
                        to_find['apple_image3_nor_access'] = True
                        to_find['signature_check'] = True

                    elif base == '6.x':
                        if xnu_version in ('6.0', '6.1.3'):
                            if xnu_version == '6.1.3':
                                to_find['cs_enforcement'] = True
                                to_find['amfi_certification'] = True
                                to_find['sandbox'] = True
                                to_find['sandbox_entitlement'] = True

                            to_find['vm_map_enter'] = True
                            to_find['tfp0'] = True
                            to_find['apple_image3_nor_access'] = True

        self.pattern_obj = Pattern(xnu_version)

        if to_find['cs_enforcement']:
            to_find['cs_enforcement'] = self.find_CSEnforcement()

        if to_find['vm_map_enter']:
            to_find['vm_map_enter'] = self.find_vm_map_enter()

        if to_find['tfp0']:
            to_find['tfp0'] = self.find_tfp0()

        if to_find['amfi_certification']:
            to_find['amfi_certification'] = self.find_AMFICertification()

        if to_find['sandbox']:
            to_find['sandbox'] = self.find_Sandbox()

        if to_find['sandbox_entitlement']:
            to_find['sandbox_entitlement'] = self.find_SandboxEntitlement()

        if to_find['amfi_memcmp']:
            to_find['amfi_memcmp'] = self.find_AMFIMemcmp()

        if to_find['apple_image3_nor_access']:
            to_find['apple_image3_nor_access'] = self.find_AppleImage3NORAccess()

        if to_find['signature_check']:
            to_find['signature_check'] = self.find_signatureCheck()

        return to_find
