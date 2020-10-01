# WinIPT
The Windows Library for Intel Process Trace (WinIPT) is a project that leverages the new Intel Processor Trace functionality exposed by Windows 10 October Update (Version 1809 / Redstone 5). The new operating system now includes the old inbox Intel PT driver (ipt.sys) with additional code that allows configuring both per-process and per-core tracing through an IOCTL and registry mechanism, instead of relying on undocumented ETW internals. In this repository, you will find the following 3 projects:

* `libipt`
This is the Win32 API version of the library which grants access to the IPT Driver/Service IOCTLs that enable per-core and per-process tracing with the new facilities exposed by Windows. This library uses Win32 semantics & notation, and its functions are re-implementations of some of the functions that were found in `Dbghelp.dll`, `Dbgcore.dll`, `TTDRecordCPU.dll`, `Faultrep.dll` and `Ntdll.dll`.

* `libiptnt`
This is the native NT API version of the same library as above, which uses only Ntdll.dll functions, making it suitable for use in Native/non-Win32 applications. This library uses NT-style semantics & notication, and its functions are almost identical to the ones exposed by the libraries listed above.

* `ipttool`
This acts as a sample for the libipt static library referenced above, and provides a simple CLI utility around starting, stopping, and querying traces for a given process. It does not currently support core tracing, and it does not do decoding -- please use the Intel PT library for that.

## Screenshot

![Screenshot](ipt-trace.png)

## Motivation

Existing Windows-focused research on Intel Processor Trace has resulted in many hand-crafted custom drivers to toggle the correct flags in the appropriate MSRs, and to register for performance interrupts to correctly handle delivery of tracing data. Unfortunately, most of these custom drivers suffer from security vulnerabilities, academic/proof-of-concept quality code, and don't handle edge and corner cases safely (as would be expected of non-commercial, paid, software!). Additionally, the techniques they use for enabling such functionality closely mimic malicious code, making it hard for defenders to distinguish between the intent of an Intel PT tracing driver, and a rootkit.

Likely in response, in Windows 10 Spring Update (Version 1803 / Redstone 4), Microsoft added an `Ipt.sys` driver that enables Intel PT support for certain classes of ETW tracing operations. The support was incomplete, and mainly to handle this specific use case. In Windows 10 October Update (Version 1809 / Redstone 5), however, Microsoft has enhanced this driver to support non-ETW-based usage of Intel PT, and to configure both per-process (per-thread) tracing as well as full per-core tracing, exposing many (but not all) of the Intel PT controls that normally get written into the appropriate MSR (such as allowing callers to enable MTC/TSC timing packets, or by configuring either Ring 0 or Ring 3 tracing).

Currently, this support seems to be specific to PSS/OCA scenarios (Microsoft's crash analytics framework part of Windows Error Reporting, or WER) and Time Travel Debugging (TTD/Nirvana) and undocumented, exposed only through a few external exports inside of `Ntdll.dll` and internal APIs inside of `Faultrep.dll`. As a result, I reverse engineered the internal IOCTL interface, the exported APIs, the tracing options and headers, and provide this library so that it may help those building PT-based tools to focus on the tracing data, and avoid having to become kernel programmers.

## Caveat

As per my previous note on existing drivers being of PoC-level quality, this repository is also a PoC and all of the libraries and tool presented here are provided with zero guarantees on their functionality, and no support (I will, however, strive to address PRs and other helpful comments!). Please do not ship commercial/enteprise/paid products using this library -- I am sure Microsoft and Intel will eventually ship an official set of APIs or SDK for such purposes.

## References

The official specification of Intel Processor Trace is available from [Intel](https://software.intel.com/en-us/blogs/2013/09/18/processor-tracing) and shoudl be perused if this is your first time learning about this technology.

For some highly recommended reading on potential applications to security, I suggest reading the following presentations from Richard Johnson & Andrea Alevi: [Go Speed Tracer](https://talos-intelligence-site.s3.amazonaws.com/production/document_files/files/000/000/048/original/Go_Speed_Tracer.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIXACIED2SPMSC7GA%2F20180711%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20180711T075012Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=7b8003bc3582e408522594913240c92a0608201f716f607111973d8c17eeafa2), [Harnessing Intel Processor Trace on Windows for Vulnerability Disclosure](https://conference.hitb.org/hitbsecconf2017ams/materials/D1T1%20-%20Richard%20Johnson%20-%20Harnessing%20Intel%20Processor%20Trace%20on%20Windows%20for%20Vulnerability%20Discovery.pdf) as well as this presentation: [COFI Break](https://gsec.hitb.org/materials/sg2016/D2%20-%20Shlomi%20Oberman%20and%20Ron%20Shina%20-%20Breaking%20Exploits%20with%20Practical%20Control%20Flow%20Integrity.pdf) by Shlomi Oberman and Ron Shina. 

You can also get the unofficial driver which Andrea and Richard collaborated on from [GitHub](https://github.com/intelpt/WindowsIntelPT).

Other relevant research on Intel PT security applications can be found from Microsoft Research [GRIFFIN](https://www.microsoft.com/en-us/research/wp-content/uploads/2017/01/griffin-asplos17.pdf) and from Shanghai University [FlowGuard](https://ipads.se.sjtu.edu.cn/lib/exe/fetch.php?media=publications:flowguard.pdf).

If you would like to know more about my research or work, I invite you to check out my blog at [http://www.alex-ionescu.com](http://www.alex-ionescu.com) as well as my training & consulting company, Winsider Seminars & Solutions Inc., at [http://www.windows-internals.com](http://www.windows-internals.com).

## License

```
Copyright 2018 Alex Ionescu. All rights reserved. 

Redistribution and use in source and binary forms, with or without modification, are permitted provided
that the following conditions are met: 
1. Redistributions of source code must retain the above copyright notice, this list of conditions and
   the following disclaimer. 
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions
   and the following disclaimer in the documentation and/or other materials provided with the 
   distribution. 

THIS SOFTWARE IS PROVIDED BY ALEX IONESCU ``AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL ALEX IONESCU
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those of the authors and
should not be interpreted as representing official policies, either expressed or implied, of Alex Ionescu.
```
