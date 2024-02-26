
import sys
from collections import namedtuple
from typing import Optional

from .kplist import kplist_parse
from .utils import getAllNullTerminatedStrings, unpackToDictWithKeys


class MachOError(Exception):
    pass


class MachO:
    MACHO_MAGIC = b'\xfe\xed\xfa\xce'

    MACH_HEADER_SIZE = 28

    MACH_HEADER = namedtuple(
        'MACH_HEADER',
        (
            'magic',
            'cputype',
            'cpusubtype',
            'filetype',
            'ncmds',
            'sizeofcmds',
            'flags'
        )
    )

    LOAD_COMMAND_SIZE = 8

    LOAD_COMMAND = namedtuple(
        'LOAD_COMMAND',
        (
            'cmd',
            'cmdsize'
        )
    )

    SEGMENT_COMMAND_SIZE = 56

    SEGMENT_COMMAND = namedtuple(
        'SEGMENT_COMMAND',
        (
            'cmd',
            'cmdsize',
            'segname',
            'vmaddr',
            'vmsize',
            'fileoff',
            'filesize',
            'maxprot',
            'initprot',
            'nsects',
            'flags'
        )
    )

    SECTION_SIZE = 68

    SECTION = namedtuple(
        'SECTION',
        (
            'sectname',
            'segname',
            'addr',
            'size',
            'offset',
            'align',
            'reloff',
            'nreloc',
            'flags',
            'reserved1',
            'reserved2',
        )
    )

    SYMTAB_COMMAND_SIZE = 24

    SYMTAB_COMMAND = namedtuple(
        'SYMTAB_COMMAND',
        (
            'cmd',
            'cmdsize',
            'symoff',
            'nsyms',
            'stroff',
            'strsize'
        )
    )

    # Symbol struct below is actually called
    # "nlist", but I don't like how that's named.
    # Keeping this a "SYMBOL" struct is much more
    # readable.

    SYMBOL_SIZE = 12

    SYMBOL = namedtuple(
        'SYMBOL',
        (
            'n_strx',
            'n_type',
            'n_sect',
            'n_desc',
            'n_value'
        )
    )

    UUID_COMMAND_SIZE = 24

    UUID_COMMAND = namedtuple(
        'UUID_COMMAND',
        (
            'cmd',
            'cmdsize',
            'uuid'
        )
    )

    KMOD_INFO_SIZE = 168

    KMOD_INFO = namedtuple(
        'KMOD_INFO',
        (
            'next',
            'info_version',
            'id',
            'name',
            'version',
            'reference_count',
            'reference_list',
            'address',
            'size',
            'hdr_size',
            'start',
            'stop'
        )
    )

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.size = len(data)

        self.head = self.readHeadAndSegments(0)
        self.symbols = self.readSymbolTable(self.head['size'])
        self.prelink_info = self.getPrelinkInfo()

    def readMachoHeader(self, offset: int) -> dict:
        head_data = self.data[offset:offset+self.MACH_HEADER_SIZE]
        head = unpackToDictWithKeys('<7I', head_data, self.MACH_HEADER)
        return head

    def readSegmentCommand(self, offset: int) -> dict:
        segment_command_data = self.data[offset:offset +
                                         self.SEGMENT_COMMAND_SIZE]
        segment_command = unpackToDictWithKeys(
            '<2I16s8I', segment_command_data, self.SEGMENT_COMMAND)
        return segment_command

    def readSection(self, offset: int) -> dict:
        section_data = self.data[offset:offset + self.SECTION_SIZE]
        section = unpackToDictWithKeys('<16s16s9I', section_data, self.SECTION)
        return section

    def readSymbol(self, offset: int) -> dict:
        symbol_data = self.data[offset:offset+self.SYMBOL_SIZE]
        symbol = unpackToDictWithKeys('<I2BHI', symbol_data, self.SYMBOL)
        return symbol

    def readSymbolTable(self, offset: int) -> tuple:
        symbol_table = self.readSymbolCommand(offset)

        n_symbols = symbol_table['nsyms']

        symbol_data_len = n_symbols * self.SYMBOL_SIZE

        symbol_offset = symbol_table['symoff']

        symbols = []

        for i in range(0, symbol_data_len, self.SYMBOL_SIZE):
            symbol = self.readSymbol(symbol_offset + i)

            symbols.append(symbol)

        # strings

        strings_offset = symbol_table['stroff']
        strings_len = symbol_table['strsize']

        strings_data = self.data[strings_offset:strings_offset+strings_len]

        strings = getAllNullTerminatedStrings(strings_data)

        # Guessing here, but I'm assuming that for every symbol,
        # the order of strings equates to each symbol offset?

        # For example, first symbol is constructors_used.
        # So first string in "strings" is that string, which
        # it is, for me at least.

        return symbols, strings

    def printSymbolStrings(self) -> None:
        symbols, strings = self.readSymbolTable()

        # TODO
        # Maybe print the rest of symbol info?

        for symbol, string in zip(symbols, strings):
            sys.stderr.write(f'Symbol: {string}\n')
            sys.stderr.write(f'Pointer: 0x{symbol["n_value"]:x}\n')

    def readHeadAndSegments(self, offset: int) -> dict:
        info = {
            'header': None,
            'segments': None,
            'size': None
        }

        info['header'] = self.readMachoHeader(offset)
        n_cmds = info['header']['ncmds']

        offset += self.MACH_HEADER_SIZE

        segments = []

        for _ in range(n_cmds):
            segment = self.readSegmentCommand(offset)
            cmd = segment['cmd']

            # Honestly not sure why "n_cmds" is 12 for me
            # even though there's only 8 "actual" segments.

            # After the 9th segment, is the symbol table.

            if cmd != 1:
                # TODO This is likely not good to do...
                break

            n_sects = segment['nsects']

            offset += self.SEGMENT_COMMAND_SIZE

            sections = [] if n_sects != 0 else None

            for _ in range(n_sects):
                section = self.readSection(offset)

                offset += self.SECTION_SIZE

                sections.append(section)

            segments.append([segment, sections])

        info['segments'] = segments
        info['size'] = offset

        return info

    def findAllMachoMagicOffsets(self, data: Optional[bytes] = None) -> list:
        MAGIC = self.MACHO_MAGIC[::-1]

        if data is None:
            data = self.data

        offsets = []

        for i in range(0, len(data), 4):
            buffer = data[i:i+4]

            if buffer != MAGIC:
                continue

            offsets.append(i)

        return offsets

    def printInfo(self) -> None:
        for segment, sections in self.segments:
            sys.stderr.write('SEGMENT:\n')

            for k, v in segment.items():
                if k == 'segname':
                    v = v.translate(None, b'\x00')
                    sys.stderr.write(f'\t{k}: {v}\n')
                else:
                    sys.stderr.write(f'\t{k}: {hex(v)}\n')

            if sections is None:
                continue

            for section in sections:
                sys.stderr.write('SECTION:\n')

                for k, v in section.items():
                    if k in ('sectname', 'segname'):
                        v = v.translate(None, b'\x00')
                        sys.stderr.write(f'\t{k}: {v}\n')
                    else:
                        sys.stderr.write(f'\t{k}: {hex(v)}\n')

        sys.stderr.write(f'{self.duration}\n')

    def getSegmentWithName(self, name: bytes) -> list | None:
        segments = self.head['segments']

        match = None

        for i, (segment, _) in enumerate(segments):
            segname = segment['segname'].translate(None, b'\x00')

            if segname != name:
                continue

            match = segments[i]

        return match

    def getSectionWithName(self, segment: bytes, name: bytes) -> dict:
        pass

    def getSectionData(self, name: bytes) -> bytes:
        pass

    def getSegmentData(self, name: bytes) -> bytes:
        segment, sections = self.getSegmentWithName(name)

        offset = segment['fileoff']
        size = segment['filesize']

        data = self.data[offset:offset+size]

        return data

    def getSegmentEndOffset(self, name: bytes) -> int:
        i = self.MACH_HEADER_SIZE

        for segment, sections in self.segments:
            i += segment['cmdsize']

            if segment['segname'].startswith(name):
                break

        return i

    def readSymbolCommand(self, offset: int) -> dict:
        symbol_command_data = self.data[offset:offset+self.SYMTAB_COMMAND_SIZE]
        symbol_command = unpackToDictWithKeys(
            '<6I', symbol_command_data, self.SYMTAB_COMMAND)
        return symbol_command

    def readUUIDCommand(self, offset: int) -> dict:
        # This occurs after the symbol table command (3.0 iPhone2,1)
        uuid_command_data = self.data[offset:offset+self.UUID_COMMAND_SIZE]
        uuid_command = unpackToDictWithKeys(
            '<2I16s', uuid_command_data, self.UUID_COMMAND)
        return uuid_command

    def readUnixThread(self, offset: int) -> dict:
        # This occurs after the uuid_command (3.0 iPhone2,1)
        pass

    def getPrelinkInfo(self) -> dict:
        NAME = b'__PRELINK_INFO'

        segments = self.head['segments']

        for segment, sections in segments:
            if not segment['segname'].startswith(NAME):
                continue

            break

        offset = sections[0]['offset']
        data = self.data[offset:offset+sections[0]['size'] - 1]

        plist_data = kplist_parse(data)

        return plist_data

    def readKmodInfo(self, offset: int) -> dict:
        kmod_info_data = self.data[offset:offset+self.KMOD_INFO_SIZE]
        kmod_info = unpackToDictWithKeys(
            '<I2i64s64si6I', kmod_info_data, self.KMOD_INFO)
        return kmod_info

    def findAllKModInfo(self) -> list:
        # I'm not sure how to get this without brute-forcing it.
        # Apparently I can get information about where these are
        # from PRELINK_INFO.__INFO?

        KMOD_INFO_START = (
            b'\x00\x00\x00\x00',
            b'\x01\x00\x00\x00',
            b'\xFF\xFF\xFF\xFF'
        )

        KMOD_STR = b''.join(KMOD_INFO_START)

        kmods = []

        for i in range(0, len(self.data), 16):
            buffer = self.data[i:i+16]

            if not buffer.startswith(KMOD_STR):
                continue

            kmod_info = self.readKmodInfo(i)
            kmods.append([i, kmod_info])

        return kmods

    def getKexts(self) -> dict:
        prelink_info = self.getPrelinkInfo()

        LOAD_ADRR_STR = '_PrelinkExecutable'
        END_ADRR_STR = '_PrelinkKmodInfo'
        KEXT_SIZE_STR = '_PrelinkExecutableSize'
        KEXT_NAME_STR = 'CFBundleIdentifier'

        kmodinfo = self.findAllKModInfo()
        magic_offsets = self.findAllMachoMagicOffsets()

        kexts = {}

        for i, info in enumerate(prelink_info):
            if LOAD_ADRR_STR not in info:
                continue

            load_addr = info[LOAD_ADRR_STR]
            data_addr = info[END_ADRR_STR]  # __DATA
            size = info[KEXT_SIZE_STR]
            name = info[KEXT_NAME_STR]

            for ii, kmod in kmodinfo:
                kmod_name = kmod['name'].translate(None, b'\x00').decode('utf-8')

                if kmod_name != name:
                    continue

                kexts[name] = {
                    'fileoff': ii,
                    'head': {
                        'load_addr': load_addr,
                        'data_addr': data_addr,
                        'size': size
                    },
                    'kmodinfo': kmod
                }

        return kexts

    def printKexts(self) -> None:
        kexts = self.getKexts()

        for kext, info in kexts.items():
            sys.stderr.write(f'{kext}\n')
            sys.stderr.write(f'Start: 0x{info["start_addr"]:x}\n')
            sys.stderr.write(f'Some end: 0x{info["end_addr"]:x}\n')
            sys.stderr.write(f'Real end: 0x{info["real_end_addr"]:x}\n')
            sys.stderr.write(f'Size: 0x{info["size"]:x}\n')
            sys.stderr.write('\n')

    def getKernelSlide(self) -> int:
        text_load_segment = self.getSegmentWithName(b'__TEXT')
        addr = text_load_segment[0]['vmaddr']
        return addr

    def getPreLinkText(self) -> dict:
        NAME = b'__PRELINK_TEXT'

        segment, sections = self.getSegmentWithName(NAME)

        offset = segment['fileoff']

        segment_head = self.readHeadAndSegments(offset)

        return segment_head

    def getPreLinkState(self) -> dict:
        NAME = b'__PRELINK_STATE'

        segment, sections = self.getSegmentWithName(NAME)

        offset = segment['fileoff']

        pass
