# About the project

This is a WIP iOS 32-bit (atm) kernel patcher. The project is by all means
not to be used in any sort of production environment. This is and will always
be a library to help understand, develop, and automate certain patches to
an iOS kernel in particular.

# How the project works

So far, the only thing that is being done is that a binary file is being
passed to find offsets with a given pattern and is patching 1 or more bytes to
disable certain aspects of a decrypted kernelcache to enable restoring unsigned
firmware. This does not patch the kernel to be used in a jailbroken environment.
That requires more patches, but will be added to this project eventually.

# What's being patched

Unfortunately, I'm not fully certain what these patches do, however I know that
the patches that are being used tie into codesigning, amfi, signature checking,
and more. I'm not aware exactly what is being patched, but the patches that are
being used are derived from the sn0wbreeze project, which provides patched iOS
ipsw's which can be used to either jailbreak or to preserve the baseband that
comes with the ipsw. So far, the patches that are from the baseband preservation
mode that sn0wbreeze offers are being used in this project.

# What versions and devices are supported

iPhone 3GS:
- 3.1.3
- 4.0, 4.0.1, 4.0.2, 4.1, 4.2.1, 4.3, 4.3.1, 4.3.2, 4.3.3
- 5.0, 5.0.1, 5.1, 5.1.1  
- 6.0, 6.0.1, 6.1, 6.1.2, 6.1.3, 6.1.6
