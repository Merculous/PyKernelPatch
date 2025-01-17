# About the project

This is a WIP iOS 32-bit (atm) kernel patcher. The project is by all means
not to be used in any sort of production environment. This is and will always
be a library to help understand, develop, and automate certain patches to
an iOS kernel in particular.

# How the project works

The kernel patcher uses PyARMFind, my ARM (THUMB) instruction finder. This
is like the patchfinder's used in iBoot32Patcher and jailbreaks. 

# What's being patched

Patches AppleImage3NORAccess.kext to allow unsigned and unpersonalized img3's
to be flashed to NOR during a pwned custom restore. This is for devices with
untethered ROM exploit only for the moment. This is ideal for devices like the
iPhone 3GS which has 24KPWN and Alloc8 exploit.

# What versions and devices are supported

iPhone 3GS:
- 3.0, 3.0.1, 3.1, 3.1.2, 3.1.3
- 4.0, 4.0.1, 4.0.2, 4.1, 4.2.1, 4.3, 4.3.1, 4.3.2, 4.3.3, 4.3.4, 4.3.5
- 5.0, 5.0.1, 5.1, 5.1.1  
