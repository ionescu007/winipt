#pragma once
#pragma warning(disable:4214)
#pragma warning(disable:4201)

//
// Version number of IPT Service IOCTL buffers
//
#define IPT_BUFFER_MAJOR_VERSION_V1         1
#define IPT_BUFFER_MAJOR_VERSION_CURRENT    IPT_BUFFER_MAJOR_VERSION_V1
#define IPT_BUFFER_MINOR_VERSION_V0         0
#define IPT_BUFFER_MINOR_VERSION_CURRENT    IPT_BUFFER_MINOR_VERSION_V0

//
// Version numbers of trace formats
//
#define IPT_TRACE_VERSION_V1                1
#define IPT_TRACE_VERSION_CURRENT           IPT_TRACE_VERSION_V1

//
// See OnProcessCreate
//
typedef enum _IPT_MATCH_SETTINGS
{
    IptMatchByAnyApp,
    IptMatchByImageFileName,
    IptMatchByAnyPackage,
    IptMatchByPackageName,
} IPT_MATCH_SETTINGS;

//
// See GetIptOptionForTracingThreads vs GetIptOptionForTracingCores
//
typedef enum _IPT_MODE_SETTINGS
{
    //
    // Set through IOCTL (IptStartCoreIptTracing)
    //
    IptCtlUserModeOnly,                 // Sets BranchEn[2000], ToPA[100], User[8]
    IptCtlKernelModeOnly,               // Sets BranchEn[2000], ToPA[100], OS[4]
    IptCtlUserAndKernelMode,            // Sets BranchEn[2000], ToPA[100], User[8], OS[4]

    //
    // Set through registry (IptOptions)
    //
    IptRegUserModeOnly,                 // Sets BranchEn[2000], ToPA[100], User[8]
    IptRegKernelModeOnly,               // Sets BranchEn[2000], ToPA[100], OS[4]
    IptRegUserAndKernelMode,            // Sets BranchEn[2000], ToPA[100], User[8], OS[4]
} IPT_MODE_SETTINGS;

typedef enum IPT_TIMING_SETTINGS
{
    IptNoTimingPackets,                 // No additional IA32_RTIT_CTL bits enabled
    IptEnableMtcPackets,                // Sets MTCEn[400], TSCEn[200]. Requires CPUID.(EAX=014H,ECX=0H):EBX[3]= 1
    IptEnableCycPackets                 // Sets MTCEn[400], TSCEn[200], CYCEn[2]. Requires CPUID.(EAX=014H,ECX=0H):EBX[1]= 1
} IPT_TIMING_SETTINGS;

//
// See CheckIptOption
//
typedef union _IPT_OPTIONS
{
    struct
    {
        ULONGLONG OptionVersion : 4;    // Must be set to 1
        ULONGLONG TimingSettings : 4;   // IPT_TIMING_SETTINGS

        ULONGLONG MtcFrequency : 4;     // Bits 14:17 in IA32_RTIT_CTL
        ULONGLONG CycThreshold : 4;     // Bits 19:22 in IA32_RTIT_CTL

        ULONGLONG TopaPagesPow2 : 4;    // Size of buffer in ToPA, as 4KB powers of 2 (4KB->128MB). Multiple buffers will be used if CPUID.(EAX=014H,ECX=0H):ECX[1]= 1
        ULONGLONG MatchSettings: 3;     // IPT_MATCH_SETTINGS
        ULONGLONG Inherit : 1;          // Children will be automatically added to the trace

        ULONGLONG ModeSettings : 4;     // IPT_MODE_SETTINGS
        ULONGLONG Reserved : 36;
    };
    ULONGLONG AsULonglong;
} IPT_OPTIONS, *PIPT_OPTIONS;
C_ASSERT(sizeof(IPT_OPTIONS) == 8);

typedef struct _IPT_TRACE_DATA
{
    USHORT TraceVersion;
    USHORT ValidTrace;
    ULONG TraceSize;
    UCHAR TraceData[ANYSIZE_ARRAY];
} IPT_TRACE_DATA, *PIPT_TRACE_DATA;

typedef struct _IPT_TRACE_HEADER
{
    HANDLE ThreadId;
    IPT_TIMING_SETTINGS TimingSettings;
    ULONG MtcFrequency;
    ULONG FrequencyToTscRatio;
    ULONG UnknownSize;
    ULONG TraceSize;
    UCHAR Trace[ANYSIZE_ARRAY];
} IPT_TRACE_HEADER, *PIPT_TRACE_HEADER;

BOOL
GetIptBufferVersion (
    _Out_ PDWORD pdwBufferMajorVersion
);

BOOL
GetIptTraceVersion (
    _Out_ PWORD pwTraceVersion
);

BOOL
GetProcessIptTraceSize (
    _In_ HANDLE hProcess,
    _Out_ PDWORD pdwTraceSize
);

BOOL
GetProcessIptTrace (
    _In_ HANDLE hProcess,
    _In_ PVOID pTrace,
    _In_ DWORD dwTraceSize
);

BOOL
StartProcessIptTrace (
    _In_ HANDLE hProcess,
    _In_ IPT_OPTIONS ullOptions
);

BOOL
StopProcessIptTrace (
    _In_ HANDLE hProcess
);

BOOL
StartCoreIptTracing (
    _In_ IPT_OPTIONS ullOptions,
    _In_ DWORD dwNumberOfTries,
    _In_ DWORD dwTraceDurationInSeconds
);

NTSTATUS
RegisterExtendedImageForIptTracing (
    _In_ PWCHAR pwszImagePath,
    _In_opt_ PWCHAR pwszFilteredPath,
    _In_ IPT_OPTIONS ullOptions,
    _In_ DWORD dwNumberOfTries,
    _In_ DWORD dwTraceDurationInSeconds
);
