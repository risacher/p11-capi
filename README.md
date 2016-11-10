# p11-capi
A pkcs11 implementation on top of win32 (or win64) capi

    Copyright 2008 Stef Walter
    Copyright 2016 Dan Risacher

"p11-capi" is a module that allows Firefox (and possibly other applications) to talk to smartcards (or other cryptographic tokens) on Microsoft Windows computers. This is particularly useful on Windows 7 and later, which natively support some smartcards, but do not provide the cross-platform API used by programs like Firefox. 

There are two main interfaces for computer applications to interface with smartcards and other hardware security modules. The PKCS#11 interface is a cross-platform, de-facto industry standard API. Microsoft CAPI is a proprietary interface only supported on Windows platforms, but as Windows has significant market-share in large enterprises that use smartcards, it is more frequently supported.

This version has minor changes from Stef Walter's 2008 release. In particular, it fixes support for [SHA-2](https://en.wikipedia.org/wiki/SHA-2) (i.e. SHA256, SHA384 and SHA512) in certain situations.

I am providing [32-bit](https://github.com/risacher/p11-capi/raw/master/w32/p11capi_w32.dll) and [64-bit](https://github.com/risacher/p11-capi/raw/master/w64/p11capi_w64.dll) binaries as a convenience. 

## How to use

1. [Determine if you are using the 32-bit or 64-bit version of Firefox.](https://support.mozilla.org/en-US/kb/how-do-i-tell-if-32-bit-or-64-bit)
2. Download the appropriate .DLL file ([32-bit](https://github.com/risacher/p11-capi/raw/master/w32/p11capi_w32.dll) or [64-bit](https://github.com/risacher/p11-capi/raw/master/w64/p11capi_w64.dll)) and save it somewhere.
3. Inside Firefox, go to [Options](about:preferences) → [Advanced](about:preferences#advanced) → Certificates → Security Devices → Load
4. Enter a module name (I recommend "p11-capi") and browse to the .DLL file.

If all goes well, Firefox will show the new module in the Device Manager window, and all of the certificate categories from the Windows certificate stores.  

If all doesn't go well, please open an issue here on GitHub.

-----
    SHA-256 sums:
    133e74cd9ea57467da1b25b54bb9511eb3d8d02164f39d23243efdc9941e4909  w32/p11capi_w32.dll
    69ca3f2c0ae5189e3a205fa1dabb78593a96538d4b11dcfeefab399e7f3631fc  w64/p11capi_w64.dll
    
