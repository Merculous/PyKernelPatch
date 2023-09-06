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

So far, iOS 5.x is supported for iPhone 3GS. The patches themselves should be
very close or exactly the same. Only real differences between devices is where
everything gets loaded. 5.x have been tested and all of them restore without
issues.

# Issues

iOS 4 and 6 are not supported currently. I'm not aware of what needs to be fixed,
but I will look into it when I get the chance. For iOS 6, it is restored_external
related. I'm not sure what to do, however it involves tickets. I'm assuming ApTicket?
Anyway, I will be focusing on adding jailbreak support for iOS 5 for now.
