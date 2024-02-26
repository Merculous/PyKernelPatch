
from functools import cached_property
from typing import Tuple

from eyepatch import ARMPatcher
from eyepatch.arm import Insn, THUMB_BITWISE

from .errors import ArchError, BadKernel
from .macho import MachO


class Finder(ARMPatcher):
    def __init__(self, data: bytes):
        super().__init__(data)

        self.macho = MachO(self.data)
        # self.kexts = self.macho.getKexts()

    @cached_property
    def base_addr(self) -> int:
        return self.macho.getKernelSlide()

    def lookForOffsetInSymTable(self, name: bytes) -> int | None:
        symbols, strings = self.macho.symbols

        offset = None

        for symbol, string in zip(symbols, strings):
            if string != name:
                continue

            offset = symbol['n_value']
            break

        # Subtract base_addr from offset to get file offset
        offset -= self.base_addr

        return offset

    @cached_property
    def vm_fault_enter(self) -> Insn:
        VM_STR = b'_vm_fault_enter'

        offset = self.lookForOffsetInSymTable(VM_STR)

        if offset is None:
            pass

        return offset

    @cached_property
    def cs_enforcement_disable(self) -> Insn:
        DISABLE_STR = b'_cs_enforcement_disable'

        offset = self.lookForOffsetInSymTable(DISABLE_STR)

        if offset is None:
            # String is referenced in _vm_fault_enter
            pass

        return offset

    @cached_property
    def apple_image3_nor_access(self) -> Tuple[Insn]:
        # Dev string should only be referenced once
        DEV_STR = b'development-cert'
        dev = self.search_string(DEV_STR)
        dev_ldr = self.search_xref(dev.offset, self.base_addr, is_kernel=True)

        # Find PROD LDR, followed by BL.

        PROD_STR = int.from_bytes(b'PROD')
        prod_ldr = self.search_imm(PROD_STR, dev_ldr.offset)
        prod_bl = self.search_insn('bl', prod_ldr.offset)

        # Find ECID LDR, followed by BL.

        ECID_STR = int.from_bytes(b'ECID')
        ecid_ldr = self.search_imm(ECID_STR, prod_bl.offset)
        ecid_bl = self.search_insn('bl', ecid_ldr.offset)

        # Find SHSH LDR, followed by CMP and BL.

        SHSH_STR = int.from_bytes(b'SHSH')
        shsh_ldr = self.search_imm(SHSH_STR, ecid_bl.offset, skip=2)

        # This could be switched to .search_insn() instead but this is fine atm.
        shsh_cmp = self.search_imm(0, shsh_ldr.offset, skip=1)
        shsh_bl = self.search_insn('bl', shsh_cmp.offset)

        shsh_memmove_bl = self.search_insn('bl', shsh_bl.offset, skip=4)

        # This occurs after "development-cert"
        RSA_STR = b'Apple Secure Boot Certification Authority'
        rsa = self.search_string(RSA_STR, dev.offset)
        rsa_ldr = self.search_xref(rsa.offset, self.base_addr, is_kernel=True)
        rsa_mov = self.search_imm(-1, rsa_ldr.offset)

        return prod_bl, ecid_bl, shsh_cmp, shsh_bl, shsh_memmove_bl, rsa_mov

    @cached_property
    def pe_i_can_has_debugger(self) -> Insn:
        DEBUG_STR = b'_PE_i_can_has_debugger'

        offset = self.lookForOffsetInSymTable(DEBUG_STR)

        if offset is None:
            pass

        return offset

    @cached_property
    def task_for_pid(self) -> Insn:
        PID_STR = b'task_for_pid'

        offset = self.lookForOffsetInSymTable(PID_STR)

        if offset is None:
            pass

        return offset

    @cached_property
    def vm_map_enter(self) -> Insn:
        ENTER_STR = b'_vm_map_enter'

        offset = self.lookForOffsetInSymTable(ENTER_STR)

        if offset is None:
            pass

        bnew = self.search_insn('bne.w', offset)

        return bnew

    @cached_property
    def vm_map_protect(self) -> Insn:
        PROTECT_STR = b'_vm_map_protect'

        offset = self.lookForOffsetInSymTable(PROTECT_STR)

        if offset is None:
            pass

        return offset

    @cached_property
    def amfi_binary_trust_cache(self) -> Insn:
        REF_STR = b'missing or invalid entitlement hash\n'
        ref = self.search_string(REF_STR, exact=True)
        ref_ldr = self.search_xref(ref.offset, self.base_addr, is_kernel=True)

        # Find CBNZ, preceeded by BLX, and LDR.

        cbnz = self.search_insn('cbnz', ref_ldr.offset)
        ldr = self.search_insn('ldr', cbnz.offset, reverse=True)

        # Get the function address that's put into a register
        # via LDR.

        ldr_value = ldr.getValuePointedToByLDR(self.data, THUMB_BITWISE)
        func_start = ((ldr_value - self.base_addr) - 0x36000) - 1

        # Look for MOVS rX, #0

        func_movs = self.search_imm(0, func_start)

        return func_movs

    @cached_property
    def flush_dcache(self) -> Insn:
        CACHE_STR = b'_flush_dcache'

        offset = self.lookForOffsetInSymTable(CACHE_STR)

        if offset is None:
            pass

        return offset

    @cached_property
    def flush_icache(self) -> Insn:
        # Not _invalidate_icache?
        pass

    @cached_property
    def syscall0(self) -> Insn:
        pass

    @cached_property
    def nx_enable(self) -> Insn:
        pass

    @cached_property
    def iolog(self) -> Insn:
        pass

    @cached_property
    def proc_enforce(self) -> Insn:
        # Assuming this is the right symbol

        PROC_STR = b'_mac_proc_enforce'

        offset = self.lookForOffsetInSymTable(PROC_STR)

        if offset is None:
            pass

        return offset

    @cached_property
    def sandbox(self):
        pass
