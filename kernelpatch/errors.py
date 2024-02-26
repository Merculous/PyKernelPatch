
class KernelError(Exception):
    pass


class ArchError(KernelError):
    pass


class FindError(KernelError):
    pass


class PatchError(KernelError):
    pass


class BadKernel(KernelError):
    pass
