#include <Windows.h>
#include <stdio.h>
#include <libipt.h>

#define IPT_TOOL_USE_MTC_TIMING_PACKETS     0x01
#define IPT_TOOL_USE_CYC_TIMING_PACKETS     0x02
#define IPT_TOOL_TRACE_KERNEL_MODE          0x04
#define IPT_TOOL_TRACE_ALL_MODE             0x08

#define IPT_TOOL_VALID_FLAGS                \
    (IPT_TOOL_USE_MTC_TIMING_PACKETS |      \
     IPT_TOOL_USE_CYC_TIMING_PACKETS |      \
     IPT_TOOL_TRACE_KERNEL_MODE |           \
     IPT_TOOL_TRACE_ALL_MODE)

typedef enum _IPT_TL_ACTION
{
    IptTlStartTrace,
    IptTlStopTrace,
    IptTlGetTrace,
    IptTlQueryTrace,
    IptTlPauseTrace,
    IptTlResumeTrace,
    IptTlConfigureFilter,
    IptTlQueryFilter,
    IptTlQueryTraceStop,
} IPT_TL_ACTION;

FORCEINLINE
DWORD
ConvertToPASizeToSizeOption (
    _In_ DWORD dwSize
    )
{
    DWORD dwIndex;

    //
    // Cap the size to 128MB. Sizes below 4KB will result in 0 anyway.
    //
    if (dwSize > (128 * 1024 * 1024))
    {
        dwSize = 128 * 1024 * 1024;
    }

    //
    // Find the nearest power of two that's set (align down)
    //
    BitScanReverse(&dwIndex, dwSize);

    //
    // The value starts at 4KB
    //
    dwIndex -= 12;
    return dwIndex;
}

BOOL
EnableIpt (
    VOID
    )
{
    SC_HANDLE hScm, hSc;
    BOOL bRes;
    bRes = FALSE;

    //
    // Open a handle to the SCM
    //
    hScm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hScm != NULL)
    {
        //
        // Open a handle to the IPT Service
        //
        hSc = OpenService(hScm, L"Ipt", SERVICE_START);
        if (hSc != NULL)
        {
            //
            // Start it
            //
            bRes = StartService(hSc, 0, NULL);
            if ((bRes == FALSE) &&
                (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING))
            {
                //
                // If it's already started, that's OK
                //
                bRes = TRUE;
            }
            else if (bRes == FALSE)
            {
                wprintf(L"[-] Unable to start IPT Service (err=%d)\n",
                        GetLastError());
                if (GetLastError() == ERROR_NOT_SUPPORTED)
                {
                    wprintf(L"[-] This is likely due to missing PT support\n");
                }
            }

            //
            // Done with the service
            //
            CloseServiceHandle(hSc);
        }
        else
        {
            wprintf(L"[-] Unable to open IPT Service (err=%d). "
                    L"Are you running Windows 10 1809?\n",
                    GetLastError());
        }

        //
        // Done with the SCM
        //
        CloseServiceHandle(hScm);
    }
    else
    {
        wprintf(L"[-] Unable to open a handle to the SCM (err=%d)\n",
                GetLastError());
    }

    //
    // Return the result
    //
    return bRes;
}

BOOL
EnableAndValidateIptServices (
    VOID
    )
{
    WORD wTraceVersion;
    DWORD dwBufferVersion;
    BOOL bRes;

    //
    // First enable IPT
    //
    bRes = EnableIpt();
    if (bRes == FALSE)
    {
        wprintf(L"[-] Intel PT Service could not be started!\n");
        goto Cleanup;
    }

    //
    // Next, check if the driver uses a dialect we understand
    //
    bRes = GetIptBufferVersion(&dwBufferVersion);
    if (bRes == FALSE)
    {
        wprintf(L"[-] Failed to communicate with IPT Service: (err=%d)\n",
                GetLastError());
        goto Cleanup;
    }
    if (dwBufferVersion != IPT_BUFFER_MAJOR_VERSION_CURRENT)
    {
        wprintf(L"[-] IPT Service buffer version is not supported: %d\n",
                dwBufferVersion);
        goto Cleanup;
    }

    //
    // Then, check if the driver uses trace versions we speak
    //
    bRes = GetIptTraceVersion(&wTraceVersion);
    if (bRes == FALSE)
    {
        wprintf(L"[-] Failed to get Trace Version from IPT Service (err=%d)\n",
                GetLastError());
        goto Cleanup;
    }
    if (wTraceVersion != IPT_TRACE_VERSION_CURRENT)
    {
        wprintf(L"[-] IPT Service trace version is not supported %d\n",
                wTraceVersion);
        goto Cleanup;
    }

Cleanup:
    //
    // Return result
    //
    return bRes;
}

BOOL
ConfigureTraceFlags (
    _In_ PWCHAR pwszFlags,
    _Inout_ PIPT_OPTIONS pOptions
    )
{
    DWORD dwFlags;
    BOOL bRes;
    bRes = FALSE;

    //
    // Read the flags now and make sure they're valid
    //
    dwFlags = wcstoul(pwszFlags, NULL, 16);
    if (dwFlags & ~IPT_TOOL_VALID_FLAGS)
    {
        wprintf(L"[-] Invalid flags: %s\n", pwszFlags);
        goto Cleanup;
    }

    //
    // If the user didn't specify MTC, but wants CYC, set MTC too as the IPT
    // driver wil enable those packets anyway.
    //
    if ((dwFlags & IPT_TOOL_USE_CYC_TIMING_PACKETS) &&
        !(dwFlags & IPT_TOOL_USE_MTC_TIMING_PACKETS))
    {
        wprintf(L"[*] CYC Packets require MTC packets, adjusting flags!\n");
        dwFlags |= IPT_TOOL_USE_MTC_TIMING_PACKETS;
    }

    //
    // If the user didn't specify MTC, but wants CYC, set MTC too as the IPT
    // driver wil enable those packets anyway.
    //
    if ((dwFlags & (IPT_TOOL_TRACE_KERNEL_MODE | IPT_TOOL_TRACE_ALL_MODE)) ==
        (IPT_TOOL_TRACE_KERNEL_MODE | IPT_TOOL_TRACE_ALL_MODE))
    {
        wprintf(L"[-] Cannot enable both `kernel` and `user + kernel` tracing."
                L" Please pick a single flag to use!\n");
        goto Cleanup;
    }

    //
    // There are no matching options for process tradces
    //
    pOptions->MatchSettings = IptMatchByAnyApp;

    //
    // Choose the right timing setting
    //
    if (dwFlags & IPT_TOOL_USE_MTC_TIMING_PACKETS)
    {
        pOptions->TimingSettings = IptEnableMtcPackets;
        pOptions->MtcFrequency = 3; // FIXME
    }
    else if (dwFlags & IPT_TOOL_USE_CYC_TIMING_PACKETS)
    {
        pOptions->TimingSettings = IptEnableCycPackets;
        pOptions->CycThreshold = 1; // FIXME
    }
    else
    {
        pOptions->TimingSettings = IptNoTimingPackets;
    }

    //
    // Choose the right mode setting
    //
    if (dwFlags & IPT_TOOL_TRACE_KERNEL_MODE)
    {
        pOptions->ModeSettings = IptCtlKernelModeOnly;
    }
    else if (dwFlags & IPT_TOOL_TRACE_ALL_MODE)
    {
        pOptions->ModeSettings = IptCtlUserAndKernelMode;
    }
    else
    {
        pOptions->ModeSettings = IptCtlUserModeOnly;
    }

    //
    // Print out chosen options
    //
    bRes = TRUE;
    wprintf(L"[+] Tracing Options:\n"
            L"           Match by: %s\n"
            L"         Trace mode: %s\n"
            L"     Timing packets: %s\n",
            L"Any process",
            (pOptions->ModeSettings == IptCtlUserAndKernelMode) ?
            L"Kernel and user-mode" :
            (pOptions->ModeSettings == IptCtlKernelModeOnly) ?
            L"Kernel-mode only" : L"User-mode only",
            (pOptions->TimingSettings == IptEnableMtcPackets) ?
            L"MTC Packets" :
            (pOptions->TimingSettings == IptEnableCycPackets) ?
            L"CYC Packets" : L"No  Packets");

Cleanup:
    //
    // Return result
    //
    return bRes;
}

BOOL
ConfigureBufferSize (
    _In_ PWCHAR pwszSize,
    _Inout_ PIPT_OPTIONS pOptions
    )
{
    DWORD dwSize;
    BOOL bRes;
    bRes = FALSE;

    //
    // Get the buffer size
    //
    dwSize = wcstoul(pwszSize, NULL, 10);
    if (dwSize == 0)
    {
        wprintf(L"[-] Invalid size: %s\n", pwszSize);
        goto Cleanup;
    }

    //
    // Warn the user about incorrect values
    //
    if (!((dwSize) && ((dwSize & (~dwSize + 1)) == dwSize)))
    {
        wprintf(L"[*] Size will be aligned to a power of 2\n");
    }
    else if (dwSize < 4096)
    {
        wprintf(L"[*] Size will be set to minimum of 4KB\n");
    }
    else if (dwSize > (128 * 1024 * 1024))
    {
        wprintf(L"[*] Size will be set to a maximum of 128MB\n");
    }

    //
    // Compute the size option
    //
    pOptions->TopaPagesPow2 = ConvertToPASizeToSizeOption(dwSize);
    bRes = TRUE;
    wprintf(L"[+] Using size: %d bytes\n",
            1 << (pOptions->TopaPagesPow2 + 12));

Cleanup:
    //
    // Return result
    //
    return bRes;
}

BOOL
ConfigureProcess (
    _In_ PWCHAR pwszPid,
    _Out_ PHANDLE phProcess
    )
{
    DWORD dwPid;
    BOOL bRes;
    bRes = FALSE;
    *phProcess = NULL;

    //
    // Get the PID first
    //
    dwPid = wcstoul(pwszPid, NULL, 0);
    if (dwPid == 0)
    {
        wprintf(L"[-] Invalid PID: %s\n", pwszPid);
        goto Cleanup;
    }

    //
    // Open a handle to it
    //
    *phProcess = OpenProcess(PROCESS_VM_READ, FALSE, dwPid);
    if (*phProcess == NULL)
    {
        wprintf(L"[-] Unable to open PID %d (err=%d)\n",
                dwPid, GetLastError());
        goto Cleanup;
    }
    bRes = TRUE;

Cleanup:
    //
    // Return result
    //
    return bRes;
}

BOOL
ConfigureThread (
    _In_ PWCHAR pwszTid,
    _Out_ PHANDLE phThread
    )
{
    DWORD dwPid;
    BOOL bRes;
    bRes = FALSE;
    *phThread = NULL;

    //
    // Get the PID first
    //
    dwPid = wcstoul(pwszTid, NULL, 0);
    if (dwPid == 0)
    {
        wprintf(L"[-] Invalid TID: %s\n", pwszTid);
        goto Cleanup;
    }

    //
    // Open a handle to it
    //
    *phThread = OpenThread(THREAD_GET_CONTEXT, FALSE, dwPid);
    if (*phThread == NULL)
    {
        wprintf(L"[-] Unable to open TID %d (err=%d)\n",
                dwPid, GetLastError());
        goto Cleanup;
    }
    bRes = TRUE;

Cleanup:
    //
    // Return result
    //
    return bRes;
}

INT
wmain (
    _In_ DWORD dwArgumentCount,
    _In_ PWCHAR pwszArguments[]
    )
{
    BOOL bRes;
    DWORD dwTraceSize;
    HANDLE hProcess;
    HANDLE hThread;
    HANDLE hTraceFile;
    DWORD dwResult;
    IPT_TL_ACTION dwAction;
    IPT_OPTIONS options;
    PIPT_TRACE_DATA pTraceData;
    PIPT_TRACE_HEADER traceHeader;
    DWORD dwEntries;
    UINT i;
    BOOLEAN result;
    DWORD dwRangeIndex;
    IPT_FILTER_RANGE_SETTINGS dwRangeConfig;
    DWORD64 ullStartAddress;
    DWORD64 ullEndAddress;
    BOOLEAN bTraceStop;

    //
    // Setup cleanup path
    //
    hTraceFile = INVALID_HANDLE_VALUE;
    hProcess = NULL;
    hThread = NULL;
    pTraceData = NULL;
    dwResult = 0xFFFFFFFF;
    options.AsULonglong = 0;
    result = 0;
    dwRangeIndex = 0;
    dwRangeConfig = IptFilterRangeDisable;
    ullStartAddress = 0;
    ullEndAddress = 0;

    //
    // Shameless banner header
    //
    wprintf(L"/------------------------------------------\\\n");
    wprintf(L"|=== Windows 10 RS5 1809+ IPT Test Tool ===|\n");
    wprintf(L"|===  Copyright (c) 2018 Alex Ionescu   ===|\n");
    wprintf(L"|===    http://github.com/ionescu007    ===|\n");
    wprintf(L"|===  http://www.windows-internals.com  ===|\n");
    wprintf(L"\\------------------------------------------/\n");
    wprintf(L"\n");

    //
    // Print banner if invalid/no arguments
    //
    if (dwArgumentCount <= 1)
    {
Banner:
        wprintf(L"Usage: IptTool.exe [action]\n"
                L"\n"
                L"Actions:\n"
                L"--start <PID> <Size> <Flags>\n"
                L"    Starts Intel PT tracing for the given PID\n"
                L"    Size should be a power of two between 4KB-128MB in bytes\n"
                L"    Flag 0x00 - No Timing Packets, Trace only User Mode Code\n"
                L"    Flag 0x01 - Enable MTC Timing Packets\n"
                L"    Flag 0x02 - Enable CYC Timing Packets\n"
                L"    Flag 0x04 - Trace only Kernel Mode Code\n"
                L"    Flag 0x08 - Trace both User and Kernel Mode Code\n"
                L"--trace <PID> <File>\n"
                L"    Writes into the given file the current trace data for the given PID\n"
                L"--stop <PID>\n"
                L"    Stops Intel PT tracing for the specified PID\n"
                L"--query <PID>\n"
                L"    Queries the status of Intel PT tracing for the specified PID\n"
                L"--pause <TID>\n"
                L"    Pauses Intel PT tracing for the specified TID\n"
                L"--resume <TID>\n"
                L"    Resumes Intel PT tracing for the specified TID\n"
                L"--filter <TID> <RangeIndex> <StartAddress> <EndAddress> <Flags>\n"
                L"    Configures address range filtering for the specified TID\n"
                L"    Flag 0x00 - Disable address range filtering\n"
                L"    Flag 0x01 - Enable filtering by IP\n"
                L"    Flag 0x02 - Configure range as TraceStop condition\n"
                L"--query-filter <TID> <RangeIndex>\n"
                L"    Queries address range filtering status for the specified PID and RangeIndex\n"
                L"--query-stop <TID>\n"
                L"    Check if TraceStop has been triggered for the specified PID\n"
                L"\n"
                L"All operations require PROCESS_VM_READ rights to the target PID\n"
                L"or THREAD_GET_CONTEXT rights to the target TID, respectively\n");
        goto Cleanup;
    }

    //
    // Start parsing arguments
    //
    if (wcscmp(pwszArguments[1], L"--start") == 0)
    {
        //
        // Five arguments are neded to start a trace
        //
        if (dwArgumentCount != 5)
        {
            goto Banner;
        }

        //
        // Open a handle to the PID
        //
        bRes = ConfigureProcess(pwszArguments[2], &hProcess);
        if (bRes == FALSE)
        {
            goto Cleanup;
        }

        //
        // Initialize options for Intel PT Trace
        //
        options.OptionVersion = 1;

        //
        // Configure the buffer size
        //
        bRes = ConfigureBufferSize(pwszArguments[3], &options);
        if (bRes == FALSE)
        {
            goto Cleanup;
        }

        //
        // Configure the trace flag
        //
        bRes = ConfigureTraceFlags(pwszArguments[4], &options);
        if (bRes == FALSE)
        {
            goto Cleanup;
        }

        //
        // We are starting a trace, once we know the driver works
        //
        dwAction = IptTlStartTrace;
    }
    else if (wcscmp(pwszArguments[1], L"--stop") == 0)
    {
        //
        // Stopping a trace needs 3 arguments
        //
        if (dwArgumentCount != 3)
        {
            goto Banner;
        }

        //
        // Open a handle to the PID
        //
        bRes = ConfigureProcess(pwszArguments[2], &hProcess);
        if (bRes == FALSE)
        {
            goto Cleanup;
        }

        //
        // We are stopping a trace, once we know the driver works
        //
        dwAction = IptTlStopTrace;
    }
    else if (wcscmp(pwszArguments[1], L"--trace") == 0)
    {
        //
        // Writing a trace needs 4 arguments
        //
        if (dwArgumentCount != 4)
        {
            goto Banner;
        }

        //
        // Open a handle to the PID
        //
        bRes = ConfigureProcess(pwszArguments[2], &hProcess);
        if (bRes == FALSE)
        {
            goto Cleanup;
        }

        //
        // Open a handle to the trace file
        //
        hTraceFile = CreateFile(pwszArguments[3],
                                FILE_GENERIC_WRITE,
                                FILE_SHARE_READ,
                                NULL,
                                CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL,
                                NULL);
        if (hTraceFile == INVALID_HANDLE_VALUE)
        {
            wprintf(L"[-] Unable to create trace file %s (err=%d)\n",
                    pwszArguments[3],
                    GetLastError());
            goto Cleanup;
        }

        //
        // We are getting a trace, once we know the driver works
        //
        dwAction = IptTlGetTrace;
    }
    else if (wcscmp(pwszArguments[1], L"--query") == 0)
    {
        //
        // Querying process trace status needs 3 arguments
        //
        if (dwArgumentCount != 3)
        {
            goto Banner;
        }

        //
        // Open a handle to the PID
        //
        bRes = ConfigureProcess(pwszArguments[2], &hProcess);
        if (bRes == FALSE)
        {
            goto Cleanup;
        }

        //
        // We are querying process trace, once we know the driver works
        //
        dwAction = IptTlQueryTrace;
    }
    else if (wcscmp(pwszArguments[1], L"--pause") == 0)
    {
        //
        // Pausing thread trace needs 3 arguments
        //
        if (dwArgumentCount != 3)
        {
            goto Banner;
        }

        //
        // Open a handle to the TID
        //
        bRes = ConfigureThread(pwszArguments[2], &hThread);
        if (bRes == FALSE)
        {
            goto Cleanup;
        }

        //
        // We are pausing thread trace, once we know the driver works
        //
        dwAction = IptTlPauseTrace;
    }
    else if (wcscmp(pwszArguments[1], L"--resume") == 0)
    {
        //
        // Resuming thread trace needs 3 arguments
        //
        if (dwArgumentCount != 3)
        {
            goto Banner;
        }

        //
        // Open a handle to the TID
        //
        bRes = ConfigureThread(pwszArguments[2], &hThread);
        if (bRes == FALSE)
        {
            goto Cleanup;
        }

        //
        // We are resuming thread trace, once we know the driver works
        //
        dwAction = IptTlResumeTrace;
    }
    else if (wcscmp(pwszArguments[1], L"--filter") == 0)
    {
        if (dwArgumentCount != 7)
        {
            goto Banner;
        }
        
        bRes = ConfigureThread(pwszArguments[2], &hThread);
        if (bRes == FALSE)
        {
            goto Cleanup;
        }

        dwRangeIndex = wcstoul(pwszArguments[3], NULL, 0);
        ullStartAddress = wcstoull(pwszArguments[4], NULL, 16);
        ullEndAddress = wcstoull(pwszArguments[5], NULL, 16);
        if (ullStartAddress >= ullEndAddress)
        {
            wprintf(L"[-] Invalid range: %016llX-%016llX\n", ullStartAddress, ullEndAddress);
            goto Cleanup;
        }

        dwRangeConfig = wcstoull(pwszArguments[6], NULL, 0);
        if ((dwRangeConfig != IptFilterRangeDisable) && 
            (dwRangeConfig != IptFilterRangeIp) && 
            (dwRangeConfig != IptFilterRangeTraceStop))
        {
            wprintf(L"[-] Invalid flags: %u\n", dwRangeConfig);
            goto Cleanup;
        }

        dwAction = IptTlConfigureFilter;
    }
    else if (wcscmp(pwszArguments[1], L"--query-filter") == 0)
    {
        if (dwArgumentCount != 4)
        {
            goto Banner;
        }

        bRes = ConfigureThread(pwszArguments[2], &hThread);
        if (bRes == FALSE)
        {
            goto Cleanup;
        }

        dwRangeIndex = wcstoul(pwszArguments[3], NULL, 0);
        dwAction = IptTlQueryFilter;
    }
    else if (wcscmp(pwszArguments[1], L"--query-stop") == 0)
    {
        if (dwArgumentCount != 3)
        {
            goto Banner;
        }

        bRes = ConfigureThread(pwszArguments[2], &hThread);
        if (bRes == FALSE)
        {
            goto Cleanup;
        }

        dwAction = IptTlQueryTraceStop;
    }
    else
    {
        goto Banner;
    }

    //
    // Enable and validate IPT support works
    //
    bRes = EnableAndValidateIptServices();
    if (bRes == FALSE)
    {
        goto Cleanup;
    }

    //
    // Check what we're doing
    //
    switch (dwAction)
    {
        case IptTlStartTrace:
        {
            //
            // Start the trace
            //
            bRes = StartProcessIptTracing(hProcess, options);
            if (bRes == FALSE)
            {
                wprintf(L"[-] Failed to start a trace (err=%d)\n",
                        GetLastError());
                goto Cleanup;
            }

            //
            // Print out the status
            //
            wprintf(L"[+] Trace for PID %s started\n",
                    pwszArguments[2]);
            dwResult = 0;
            break;
        }

        case IptTlStopTrace:
        {
            //
            // Stop the trace
            //
            bRes = StopProcessIptTracing(hProcess);
            if (bRes == FALSE)
            {
                wprintf(L"[-] Failed to stop the trace (err=%d)\n",
                        GetLastError());
                goto Cleanup;
            }

            //
            // Print out the status
            //
            wprintf(L"[+] Trace for PID %s stopped\n",
                    pwszArguments[2]);
            dwResult = 0;
            break;
        }

        case IptTlQueryTrace:
        {
            //
            // Query the trace
            //
            bRes = QueryProcessIptTracing(hProcess, &options);
            if (bRes == FALSE)
            {
                wprintf(L"[-] Tracing is not enabled for this process\n");
                goto Cleanup;
            }

            //
            // Print out the status
            //
            wprintf(L"[+] Tracing Options:\n"
                    L"           Match by: %s\n"
                    L"         Trace mode: %s\n"
                    L"     Timing packets: %s\n",
                    L"Any process",
                    (options.ModeSettings == IptCtlUserAndKernelMode) ?
                    L"Kernel and user-mode" :
                    (options.ModeSettings == IptCtlKernelModeOnly) ?
                    L"Kernel-mode only" : L"User-mode only",
                    (options.TimingSettings == IptEnableMtcPackets) ?
                    L"MTC Packets" :
                    (options.TimingSettings == IptEnableCycPackets) ?
                    L"CYC Packets" : L"No  Packets");
            dwResult = 0;
            break;
        }

        case IptTlPauseTrace:
        {
            //
            // Pause tracing for this thread
            //
            bRes = PauseThreadIptTracing(hThread, &result);
            if (bRes == FALSE)
            {
                wprintf(L"[-] Failed to pause the trace (err=%d)\n",
                        GetLastError());
                goto Cleanup;
            }

            //
            // Print result
            //
            wprintf(L"Trace for TID %s paused, it was previously %s\n",
                    pwszArguments[2],
                    (result == 1) ? L"active" : L"paused");
            dwResult = 0;
            break;
        }

        case IptTlResumeTrace:
        {
            //
            // Resume tracing for this thread
            //
            bRes = ResumeThreadIptTracing(hThread, &result);
            if (bRes == FALSE)
            {
                wprintf(L"[-] Failed to resume the trace (err=%d)\n",
                        GetLastError());
                goto Cleanup;
            }

            //
            // Print result
            //
            wprintf(L"Trace for TID %s resumed, it was previously %s\n",
                    pwszArguments[2],
                    (result == 1) ? L"active" : L"paused");
            dwResult = 0;
            break;
        }

        case IptTlGetTrace:
        {
            //
            // Get the size of the trace
            //
            bRes = GetProcessIptTraceSize(hProcess, &dwTraceSize);
            if (bRes == FALSE)
            {
                wprintf(L"[-] Failed to query trace size (err=%d). "
                        L"Are you sure one is active?\n",
                        GetLastError());
                goto Cleanup;
            }

            //
            // Allocate a local buffer
            //
            pTraceData = HeapAlloc(GetProcessHeap(),
                                   HEAP_ZERO_MEMORY,
                                   dwTraceSize);
            if (pTraceData == NULL)
            {
                wprintf(L"[-] Out of memory while trying to allocate trace data\n");
                goto Cleanup;
            }

            //
            // Query the trace
            //
            wprintf(L"[+] Found active trace with %d bytes so far\n", dwTraceSize);
            bRes = GetProcessIptTrace(hProcess, pTraceData, dwTraceSize);
            if (bRes == FALSE)
            {
                wprintf(L"[-] Failed to query trace (err=%d)\n",
                        GetLastError());
                goto Cleanup;
            }

            //
            // Compute the number of thread entries in the trace data
            //
            dwEntries = (dwTraceSize - (dwTraceSize & ~0xFFF)) /
                         FIELD_OFFSET(IPT_TRACE_HEADER, Trace);
            wprintf(L"    [+] Trace contains %d thread headers\n", dwEntries);

            //
            // Parse each entry
            //
            traceHeader = (PIPT_TRACE_HEADER)pTraceData->TraceData;
            for (i = 0; i < dwEntries; i++)
            {
                //
                // Print out information from it
                //
                wprintf(L"        [+] Trace Entry %d for TID %llX\n",
                        i,
                        traceHeader->ThreadId);
                wprintf(L"               Trace Size: %08d     "
                        L"        [Ring Buffer Offset: %d]\n",
                        traceHeader->TraceSize,
                        traceHeader->RingBufferOffset);
                wprintf(L"              Timing Mode: %s  "
                        L"        [MTC Frequency: %d, ClockTsc Ratio: %d]\n",
                        (traceHeader->TimingSettings == IptEnableMtcPackets) ?
                        L"MTC Packets" :
                        (traceHeader->TimingSettings == IptEnableCycPackets) ?
                        L"CYC Packets" : L"No  Packets",
                        traceHeader->MtcFrequency,
                        traceHeader->FrequencyToTscRatio);

                //
                // Move to the next trace header
                //
                traceHeader = (PIPT_TRACE_HEADER)(traceHeader->Trace +
                                                  traceHeader->TraceSize);
            }

            //
            // Write it to disk
            //
            bRes = WriteFile(hTraceFile,
                             pTraceData->TraceData,
                             dwTraceSize -
                             FIELD_OFFSET(IPT_TRACE_DATA, TraceData),
                             NULL,
                             NULL);
            if (bRes == FALSE)
            {
                wprintf(L"[-] Failed to write trace to disk (err=%d)\n",
                        GetLastError());
                goto Cleanup;
            }

            //
            // Print out the status
            //
            wprintf(L"[+] Trace for PID %s written to %s\n",
                    pwszArguments[2],
                    pwszArguments[3]);
            dwResult = 0;
            break;
        }

        case IptTlConfigureFilter:
        {
            bRes = ConfigureThreadAddressFilterRange(hThread, 
                                                     dwRangeIndex, 
                                                     dwRangeConfig, 
                                                     ullStartAddress, 
                                                     ullEndAddress);
            if (bRes == FALSE)
            {
                wprintf(L"[-] Failed to configure address filter range (err=%d)\n",
                        GetLastError());
                goto Cleanup;
            }

            wprintf(L"[+] Address range filter configured successfully for TID %s\n",
                pwszArguments[2]);
            dwResult = 0;
            break;
        }

        case IptTlQueryFilter:
        {
            bRes = QueryThreadAddressFilterRange(hThread, 
                                                 dwRangeIndex, 
                                                 &dwRangeConfig, 
                                                 &ullStartAddress, 
                                                 &ullEndAddress);
            if (bRes == FALSE)
            {
                wprintf(L"[-] Failed to query address filter range (err=%d)\n",
                        GetLastError());
                goto Cleanup;
            }

            wprintf(L"[+] Address range filter #%u for TID %s:\n"
                    L"    Range: %016llX-%016llX\n"
                    L"    Type: %s\n",
                    dwRangeIndex,
                    pwszArguments[2],
                    ullStartAddress,
                    ullEndAddress,
                    (dwRangeConfig == IptFilterRangeDisable) ? 
                    L"Disabled" : 
                    (dwRangeConfig == IptFilterRangeIp) ? 
                    L"IP" : L"TraceStop");
            dwResult = 0;
            break;
        }

        case IptTlQueryTraceStop:
        {
            bRes = QueryThreadTraceStopRangeEntered(hThread, &bTraceStop);
            if (bRes == FALSE)
            {
                wprintf(L"[-] Failed to query address filter range (err=%d)\n",
                        GetLastError());
                goto Cleanup;
            }

            if (bTraceStop != FALSE)
            {
                wprintf(L"[+] TraceStop has been triggered for TID %s\n", 
                        pwszArguments[2]);
            }
            else
            {
                wprintf(L"[+] TraceStop has NOT been triggered for TID %s\n", 
                        pwszArguments[2]);
            }
            dwResult = 0;
            break;
        }

        DEFAULT_UNREACHABLE;
    }

Cleanup:
    //
    // Cleanup trace data if any was left over
    //
    if (pTraceData != NULL)
    {
        HeapFree(GetProcessHeap(), 0, pTraceData);
    }

    //
    // Close the trace file if we had one
    //
    if (hTraceFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hTraceFile);
    }

    //
    // Close the process handle if we had one
    //
    if (hProcess != NULL)
    {
        CloseHandle(hProcess);
    }

    //
    // Close the thread handle if we had one
    //
    if (hThread != NULL)
    {
        CloseHandle(hThread);
    }

    //
    // Return to caller
    //
    return dwResult;
}
