
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
the patches that are being used tie into codesigning and I believe a few things
regarding the AppleImage3NORAccess.kext. I'm not aware exactly what is being
patched, but the patches that are being used are derived from the sn0wbreeze
project, which provides patched iOS ipsw's which can be used to either jailbreak
or to preserve the baseband that comes with the ipsw. So far, the patches that
are from the baseband preservation mode that sn0wbreeze offers are being used
in this project.

# What versions and devices are supported

So far, iOS 5.x are supported, but only iOS 5.0.1 and 5.1.1 are for sure exact
patches. I have only restored to 5.1.1, which works, but 5.0.1 should work too.
I tried to use the patches between 5.0.1 and 5.1.1 to create 5.0 and 5.1 patches
as sn0wbreeze does not come with 5.0 or 5.1 support, at least for the iPhone 3GS.
I will be testing soon and will give updates on new iOS support. So only the iPhone
3GS is supported, but patches could also be used on another device's kernel, however
I can't guarantee anything for now.

# Additional functionality

This project also provides a diff function, although it needs updating. Note,
when diffing two kernels, they must be the same size.
