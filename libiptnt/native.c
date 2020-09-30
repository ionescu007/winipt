#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <Windows.h>
#include <winternl.h>
#include <libiptnt.h>
#include <ipt.h>

_Must_inspect_result_
__drv_allocatesMem(Mem)
__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtAllocateVirtualMemory (
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_ (*BaseAddress, _Readable_bytes_ (*RegionSize) _Writable_bytes_ (*RegionSize) _Post_readable_byte_size_ (*RegionSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
);

__kernel_entry NTSYSCALLAPI
NTSTATUS
NTAPI
NtFreeVirtualMemory (
    _In_ HANDLE ProcessHandle,
    _Inout_ __drv_freesMem(Mem) PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType
);

#define NtCurrentProcess()  ((HANDLE)-1)

FORCEINLINE
VOID
InitializeIptBuffer (
    _Inout_ PIPT_INPUT_BUFFER Buffer,
    _In_ IPT_INPUT_TYPE InputType
    )
{
    //
    // Zero it out and set the version
    //
    ZeroMemory(Buffer, sizeof(*Buffer));
    Buffer->BufferMajorVersion = IPT_BUFFER_MAJOR_VERSION_CURRENT;
    Buffer->BufferMinorVersion = IPT_BUFFER_MINOR_VERSION_CURRENT;

    //
    // Set the type
    //
    Buffer->InputType = InputType;
}

FORCEINLINE
NTSTATUS
OpenIptDevice (
    _Out_ PHANDLE IptHandle
    )
{
    UNICODE_STRING iptDriverName;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;

    //
    // Setup the device name and attributes
    //
    RtlInitUnicodeString(&iptDriverName, L"\\Device\\IPT");
    InitializeObjectAttributes(&objectAttributes,
                               &iptDriverName,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    //
    // Open the handle
    //
    return NtCreateFile(IptHandle,
                        FILE_GENERIC_READ,
                        &objectAttributes,
                        &ioStatusBlock,
                        NULL,
                        FILE_ATTRIBUTE_NORMAL,
                        FILE_SHARE_READ,
                        FILE_OPEN,
                        FILE_NO_INTERMEDIATE_BUFFERING |
                        FILE_SEQUENTIAL_ONLY |
                        FILE_NON_DIRECTORY_FILE,
                        NULL,
                        0);
}

NTSTATUS
GetIptBufferVersion (
    _Out_ PULONG BufferMajorVersion
    )
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE iptHandle;
    IPT_INPUT_BUFFER inputBuffer;
    IPT_BUFFER_VERSION outputBuffer;

    //
    // Initialize for failure
    //
    *BufferMajorVersion = 0;

    //
    // Open the IPT Device
    //
    status = OpenIptDevice(&iptHandle);
    if (NT_SUCCESS(status))
    {
        //
        // Send only the version header of the input request.
        // The type is unused.
        //
        InitializeIptBuffer(&inputBuffer, -1);
        status = NtDeviceIoControlFile(iptHandle,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &ioStatusBlock,
                                       IOCTL_IPT_REQUEST,
                                       &inputBuffer,
                                       sizeof(inputBuffer),
                                       &outputBuffer,
                                       sizeof(outputBuffer));
        NtClose(iptHandle);

        //
        // On success, return the buffer version
        //
        if (NT_SUCCESS(status))
        {
            *BufferMajorVersion = outputBuffer.BufferMajorVersion;
        }
    }
    return status;
}

NTSTATUS
GetIptTraceVersion (
    _Out_ PUSHORT TraceVersion
    )
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE iptHandle;
    IPT_INPUT_BUFFER inputBuffer;
    IPT_OUTPUT_BUFFER outputBuffer;

    //
    // Initialize for failure
    //
    *TraceVersion = 0;

    //
    // Open the IPT Device
    //
    status = OpenIptDevice(&iptHandle);
    if (NT_SUCCESS(status))
    {
        //
        // Send a request to get the trace version
        //
        InitializeIptBuffer(&inputBuffer, IptGetTraceVersion);
        status = NtDeviceIoControlFile(iptHandle,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &ioStatusBlock,
                                       IOCTL_IPT_REQUEST,
                                       &inputBuffer,
                                       sizeof(inputBuffer),
                                       &outputBuffer,
                                       sizeof(outputBuffer));
        NtClose(iptHandle);

        //
        // On success, return the buffer version
        //
        if (NT_SUCCESS(status))
        {
            *TraceVersion = outputBuffer.GetTraceVersion.TraceVersion;
        }
    }
    return status;
}

NTSTATUS
GetProcessIptTraceSize (
    _In_ HANDLE ProcessHandle,
    _Out_ PULONG TraceSize
    )
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE iptHandle;
    IPT_INPUT_BUFFER inputBuffer;
    IPT_OUTPUT_BUFFER outputBuffer;

    //
    // Initialize for failure
    //
    *TraceSize = 0;

    //
    // Open the IPT Device
    //
    status = OpenIptDevice(&iptHandle);
    if (NT_SUCCESS(status))
    {
        //
        // Send a request to get the trace size for the process
        //
        InitializeIptBuffer(&inputBuffer, IptGetProcessTraceSize);
        inputBuffer.GetProcessIptTraceSize.TraceVersion = IPT_TRACE_VERSION_CURRENT;
        inputBuffer.GetProcessIptTraceSize.ProcessHandle = (ULONG64)ProcessHandle;
        status = NtDeviceIoControlFile(iptHandle,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &ioStatusBlock,
                                       IOCTL_IPT_REQUEST,
                                       &inputBuffer,
                                       sizeof(inputBuffer),
                                       &outputBuffer,
                                       sizeof(outputBuffer));
        NtClose(iptHandle);

        //
        // Check if we got a size back
        //
        if (NT_SUCCESS(status))
        {
            //
            // The IOCTL layer supports > 4GB traces but this doesn't exist yet
            // Otherwise, return the 32-bit trace size.
            //
            if (outputBuffer.GetTraceSize.TraceSize <= ULONG_MAX)
            {
                *TraceSize = (ULONG)outputBuffer.GetTraceSize.TraceSize;
            }
            else
            {
                //
                // Mark this as a failure -- this is the Windows behavior too
                //
                status = STATUS_IMPLEMENTATION_LIMIT;
            }
        }
    }
    return status;
}

NTSTATUS
GetProcessIptTrace (
    _In_ HANDLE ProcessHandle,
    _In_ PVOID Trace,
    _In_ ULONG TraceSize
    )
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE iptHandle;
    IPT_INPUT_BUFFER inputBuffer;

    //
    // The trace comes as part of an output buffer, so that part is required
    //
    if (TraceSize < UFIELD_OFFSET(IPT_OUTPUT_BUFFER, GetTrace.TraceSize))
    {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Open the IPT Device
    //
    status = OpenIptDevice(&iptHandle);
    if (NT_SUCCESS(status))
    {
        //
        // Send a request to get the trace for the process
        //
        InitializeIptBuffer(&inputBuffer, IptGetProcessTrace);
        inputBuffer.GetProcessIptTrace.TraceVersion = IPT_TRACE_VERSION_CURRENT;
        inputBuffer.GetProcessIptTrace.ProcessHandle = (ULONG64)ProcessHandle;
        status = NtDeviceIoControlFile(iptHandle,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &ioStatusBlock,
                                       IOCTL_IPT_READ_TRACE,
                                       &inputBuffer,
                                       sizeof(inputBuffer),
                                       Trace,
                                       TraceSize);
        NtClose(iptHandle);
    }
    return status;
}

NTSTATUS
StartProcessIptTracing (
    _In_ HANDLE ProcessHandle,
    _In_ IPT_OPTIONS Options
    )
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE iptHandle;
    IPT_INPUT_BUFFER inputBuffer;
    IPT_OUTPUT_BUFFER outputBuffer;

    //
    // Open the IPT Device
    //
    status = OpenIptDevice(&iptHandle);
    if (NT_SUCCESS(status))
    {
        //
        // Send a request to start tracing for this process
        //
        InitializeIptBuffer(&inputBuffer, IptStartProcessTrace);
        inputBuffer.StartProcessIptTrace.Options = Options;
        inputBuffer.StartProcessIptTrace.ProcessHandle = (ULONG64)ProcessHandle;
        status = NtDeviceIoControlFile(iptHandle,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &ioStatusBlock,
                                       IOCTL_IPT_REQUEST,
                                       &inputBuffer,
                                       sizeof(inputBuffer),
                                       &outputBuffer,
                                       sizeof(outputBuffer));
        NtClose(iptHandle);
    }
    return status;
}

NTSTATUS
StopProcessIptTracing (
    _In_ HANDLE ProcessHandle
    )
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE iptHandle;
    IPT_INPUT_BUFFER inputBuffer;
    IPT_OUTPUT_BUFFER outputBuffer;

    //
    // Open the IPT Device
    //
    status = OpenIptDevice(&iptHandle);
    if (NT_SUCCESS(status))
    {
        //
        // Send a request to stop tracing for this process
        //
        InitializeIptBuffer(&inputBuffer, IptStopProcessTrace);
        inputBuffer.StopProcessIptTrace.ProcessHandle = (ULONG64)ProcessHandle;
        status = NtDeviceIoControlFile(iptHandle,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &ioStatusBlock,
                                       IOCTL_IPT_REQUEST,
                                       &inputBuffer,
                                       sizeof(inputBuffer),
                                       &outputBuffer,
                                       sizeof(outputBuffer));
        NtClose(iptHandle);
    }
    return status;
}

NTSTATUS
StartCoreIptTracing (
    _In_ IPT_OPTIONS Options,
    _In_ ULONG NumberOfTries,
    _In_ ULONG TraceDurationInSeconds
    )
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE iptHandle;
    IPT_INPUT_BUFFER inputBuffer;
    IPT_OUTPUT_BUFFER outputBuffer;

    //
    // Open the IPT Device
    //
    status = OpenIptDevice(&iptHandle);
    if (NT_SUCCESS(status))
    {
        //
        // Send a request to start tracing for all the processor cores
        //
        InitializeIptBuffer(&inputBuffer, IptStartCoreTracing);
        inputBuffer.StartCoreIptTracing.Options = Options;
        inputBuffer.StartCoreIptTracing.NumberOfTries = NumberOfTries;
        inputBuffer.StartCoreIptTracing.TraceDurationInSeconds = TraceDurationInSeconds;
        status = NtDeviceIoControlFile(iptHandle,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &ioStatusBlock,
                                       IOCTL_IPT_REQUEST,
                                       &inputBuffer,
                                       sizeof(inputBuffer),
                                       &outputBuffer,
                                       sizeof(outputBuffer));
        NtClose(iptHandle);
    }
    return status;
}

NTSTATUS
RegisterExtendedImageForIptTracing (
    _In_ PWCHAR ImagePath,
    _In_opt_ PWCHAR FilteredPath,
    _In_ IPT_OPTIONS Options,
    _In_ ULONG NumberOfTries,
    _In_ ULONG TraceDurationInSeconds
    )
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;
    USHORT pathLength, filterLength;
    ULONG inputLength;
    HANDLE iptHandle;
    PIPT_INPUT_BUFFER inputBuffer;
    IPT_OUTPUT_BUFFER outputBuffer;
    SIZE_T regionSize;

    //
    // Open the IPT Device
    //
    status = OpenIptDevice(&iptHandle);
    if (NT_SUCCESS(status))
    {
        //
        // Compute the size of the image path, and input buffer containing it
        //
        pathLength = (USHORT)(wcslen(ImagePath) + 1) * sizeof(WCHAR);
        inputLength = pathLength + sizeof(*inputBuffer);

        //
        // Add the IFEO filter path size if it was passed in
        //
        if (FilteredPath != NULL)
        {
            filterLength = (USHORT)(wcslen(FilteredPath) + 1) * sizeof(WCHAR);
            inputLength += filterLength;
        }

        //
        // Allocate the input buffer. Mimic Windows here by not using the heap.
        //
        inputBuffer = NULL;
        regionSize = inputLength;
        status = NtAllocateVirtualMemory(NtCurrentProcess(),
                                         &inputBuffer,
                                         0,
                                         &regionSize,
                                         MEM_COMMIT,
                                         PAGE_READWRITE);
        if (NT_SUCCESS(status))
        {
            //
            // Initialize a request for registering the given process
            //
            InitializeIptBuffer(inputBuffer, IptRegisterExtendedImageForTracing);
            inputBuffer->RegisterExtendedImageForIptTracing.Options = Options;
            inputBuffer->RegisterExtendedImageForIptTracing.NumberOfTries = NumberOfTries;
            inputBuffer->RegisterExtendedImageForIptTracing.TraceDurationInSeconds = TraceDurationInSeconds;

            //
            // Copy the image path
            //
            inputBuffer->RegisterExtendedImageForIptTracing.ImagePathLength = pathLength;
            CopyMemory(inputBuffer->RegisterExtendedImageForIptTracing.ImageName,
                       ImagePath,
                       pathLength);

            //
            // Copy the filter path if it was present
            //
            if (FilteredPath != NULL)
            {
                inputBuffer->RegisterExtendedImageForIptTracing.FilteredPathLength = filterLength;
                CopyMemory((PVOID)((ULONG_PTR)inputBuffer->RegisterExtendedImageForIptTracing.ImageName + pathLength),
                           FilteredPath,
                           filterLength);
            }
            else
            {
                inputBuffer->RegisterExtendedImageForIptTracing.FilteredPathLength = 0;
            }

            //
            // Send the request
            //
            status = NtDeviceIoControlFile(iptHandle,
                                           NULL,
                                           NULL,
                                           NULL,
                                           &ioStatusBlock,
                                           IOCTL_IPT_REQUEST,
                                           &inputBuffer,
                                           sizeof(inputBuffer),
                                           &outputBuffer,
                                           sizeof(outputBuffer));

            //
            // Free the input buffer
            //
            regionSize = 0;
            NtFreeVirtualMemory(NtCurrentProcess(),
                                &inputBuffer,
                                &regionSize,
                                MEM_RELEASE);
        }
        NtClose(iptHandle);
    }
    return status;
}

NTSTATUS
PauseThreadIptTracing (
    _In_ HANDLE ThreadHandle,
    _In_ PBOOLEAN Result
    )
{
    NTSTATUS status;
    HANDLE iptHandle;
    IO_STATUS_BLOCK ioStatusBlock;
    IPT_INPUT_BUFFER inputBuffer;
    IPT_OUTPUT_BUFFER outputBuffer;

    //
    // Open the IPT Device
    //
    status = OpenIptDevice(&iptHandle);
    if (NT_SUCCESS(status))
    {
        //
        // Send a request to pause tracing for the given thread
        //
        InitializeIptBuffer(&inputBuffer, IptPauseThreadTrace);
        inputBuffer.PauseThreadIptTrace.ThreadHandle = (ULONG64)ThreadHandle;
        status = NtDeviceIoControlFile(iptHandle,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &ioStatusBlock,
                                       IOCTL_IPT_REQUEST,
                                       &inputBuffer,
                                       sizeof(inputBuffer),
                                       &outputBuffer,
                                       sizeof(outputBuffer));
        if (NT_SUCCESS(status))
        {
            //
            // Result whether or not the thread was tracing or not
            //
            *Result = outputBuffer.PauseTrace.OldState;
        }
        NtClose(iptHandle);
    }
    return status;
}

NTSTATUS
ResumeThreadIptTracing (
    _In_ HANDLE ThreadHandle,
    _In_ PBOOLEAN Result
    )
{
    NTSTATUS status;
    HANDLE iptHandle;
    IO_STATUS_BLOCK ioStatusBlock;
    IPT_INPUT_BUFFER inputBuffer;
    IPT_OUTPUT_BUFFER outputBuffer;

    //
    // Open the IPT Device
    //
    status = OpenIptDevice(&iptHandle);
    if (NT_SUCCESS(status))
    {
        //
        // Send a request to resume tracing for the given thread
        //
        InitializeIptBuffer(&inputBuffer, IptResumeThreadTrace);
        inputBuffer.ResumeThreadIptTrace.ThreadHandle = (ULONG64)ThreadHandle;
        status = NtDeviceIoControlFile(iptHandle,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &ioStatusBlock,
                                       IOCTL_IPT_REQUEST,
                                       &inputBuffer,
                                       sizeof(inputBuffer),
                                       &outputBuffer,
                                       sizeof(outputBuffer));
        if (NT_SUCCESS(status))
        {
            //
            // Return whether or not the thread was tracing or not
            //
            *Result = outputBuffer.ResumeTrace.OldState;
        }
        NtClose(iptHandle);
    }
    return status;
}

NTSTATUS
QueryProcessIptTracing (
    _In_ HANDLE ProcessHandle,
    _Out_ PIPT_OPTIONS Options
    )
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE iptHandle;
    IPT_INPUT_BUFFER inputBuffer;
    IPT_OUTPUT_BUFFER outputBuffer;

    //
    // Open the IPT Device
    //
    status = OpenIptDevice(&iptHandle);
    if (NT_SUCCESS(status))
    {
        //
        // Send a request to check if the process has any tracing options set
        //
        InitializeIptBuffer(&inputBuffer, IptQueryProcessTrace);
        inputBuffer.QueryProcessIptTrace.ProcessHandle = (ULONG64)ProcessHandle;
        status = NtDeviceIoControlFile(iptHandle,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &ioStatusBlock,
                                       IOCTL_IPT_REQUEST,
                                       &inputBuffer,
                                       sizeof(inputBuffer),
                                       &outputBuffer,
                                       sizeof(outputBuffer));
        if (NT_SUCCESS(status))
        {
            //
            // Return the current set of options that are active
            //
            *Options = outputBuffer.QueryProcessTrace.Options;
        }
        NtClose(iptHandle);
    }
    return status;
}

NTSTATUS
QueryCoreIptTracing (
    _Out_ PIPT_OPTIONS Options
    )
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE iptHandle;
    IPT_INPUT_BUFFER inputBuffer;
    IPT_OUTPUT_BUFFER outputBuffer;

    //
    // Open the IPT Device
    //
    status = OpenIptDevice(&iptHandle);
    if (NT_SUCCESS(status))
    {
        //
        // Send a request to check if the processor has any tracing options set
        //
        InitializeIptBuffer(&inputBuffer, IptQueryCoreTrace);
        status = NtDeviceIoControlFile(iptHandle,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &ioStatusBlock,
                                       IOCTL_IPT_REQUEST,
                                       &inputBuffer,
                                       sizeof(inputBuffer),
                                       &outputBuffer,
                                       sizeof(outputBuffer));
        if (NT_SUCCESS(status))
        {
            //
            // Return the current set of options that are active
            //
            *Options = outputBuffer.QueryCoreTrace.Options;
        }
        NtClose(iptHandle);
    }
    return status;
}

NTSTATUS
StopTraceOnEachCore (
    VOID
    )
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE iptHandle;
    IPT_INPUT_BUFFER inputBuffer;
    IPT_OUTPUT_BUFFER outputBuffer;

    status = OpenIptDevice(&iptHandle);
    if (NT_SUCCESS(status))
    {
        InitializeIptBuffer(&inputBuffer, IptStopTraceOnEachCore);
        status = NtDeviceIoControlFile(iptHandle,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &ioStatusBlock,
                                       IOCTL_IPT_REQUEST,
                                       &inputBuffer,
                                       sizeof(inputBuffer),
                                       &outputBuffer,
                                       sizeof(outputBuffer));
        NtClose(iptHandle);
    }
    return status;
}

NTSTATUS
ConfigureThreadAddressFilterRange (
    _In_ HANDLE ThreadHandle,
    _In_ ULONG RangeIndex,
    _In_ IPT_FILTER_RANGE_SETTINGS RangeConfig,
    _In_ ULONG64 StartAddress,
    _In_ ULONG64 EndAddress
    )
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE iptHandle;
    IPT_INPUT_BUFFER inputBuffer;
    IPT_OUTPUT_BUFFER outputBuffer;

    status = OpenIptDevice(&iptHandle);
    if (NT_SUCCESS(status))
    {
        InitializeIptBuffer(&inputBuffer, IptConfigureThreadAddressFilterRange);
        inputBuffer.ConfigureThreadAddressFilterRange.ThreadHandle = (ULONG64)ThreadHandle;
        inputBuffer.ConfigureThreadAddressFilterRange.RangeIndex = RangeIndex;
        inputBuffer.ConfigureThreadAddressFilterRange.RangeConfig = RangeConfig;
        inputBuffer.ConfigureThreadAddressFilterRange.StartAddress = StartAddress;
        inputBuffer.ConfigureThreadAddressFilterRange.EndAddress = EndAddress;
        status = NtDeviceIoControlFile(iptHandle,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &ioStatusBlock,
                                       IOCTL_IPT_REQUEST,
                                       &inputBuffer,
                                       sizeof(inputBuffer),
                                       &outputBuffer,
                                       sizeof(outputBuffer));
        NtClose(iptHandle);
    }
    return status;
}

NTSTATUS
QueryThreadAddressFilterRange (
    _In_ HANDLE ThreadHandle,
    _In_ ULONG RangeIndex,
    _Out_ PIPT_FILTER_RANGE_SETTINGS RangeConfig,
    _Out_ PULONG64 StartAddress,
    _Out_ PULONG64 EndAddress
    )
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE iptHandle;
    IPT_INPUT_BUFFER inputBuffer;
    IPT_OUTPUT_BUFFER outputBuffer;

    status = OpenIptDevice(&iptHandle);
    if (NT_SUCCESS(status))
    {
        InitializeIptBuffer(&inputBuffer, IptQueryThreadAddressFilterRange);
        inputBuffer.QueryThreadAddressFilterRange.ThreadHandle = (ULONG64)ThreadHandle;
        inputBuffer.QueryThreadAddressFilterRange.RangeIndex = RangeIndex;
        status = NtDeviceIoControlFile(iptHandle,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &ioStatusBlock,
                                       IOCTL_IPT_REQUEST,
                                       &inputBuffer,
                                       sizeof(inputBuffer),
                                       &outputBuffer,
                                       sizeof(outputBuffer));
        if (NT_SUCCESS(status))
        {
            *RangeConfig = outputBuffer.QueryThreadAddressFilterRange.RangeConfig;
            *StartAddress = outputBuffer.QueryThreadAddressFilterRange.StartAddress;
            *EndAddress = outputBuffer.QueryThreadAddressFilterRange.EndAddress;
        }
        NtClose(iptHandle);
    }
    return status;
}

NTSTATUS
QueryThreadTraceStopRangeEntered (
    _In_ HANDLE ThreadHandle,
    _Out_ PBOOLEAN TraceStopRangeEntered
    )
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE iptHandle;
    IPT_INPUT_BUFFER inputBuffer;
    IPT_OUTPUT_BUFFER outputBuffer;

    status = OpenIptDevice(&iptHandle);
    if (NT_SUCCESS(status))
    {
        InitializeIptBuffer(&inputBuffer, IptQueryThreadTraceStopRangeEntered);
        inputBuffer.QueryThreadTraceStopRangeEntered.ThreadHandle = (ULONG64)ThreadHandle;
        status = NtDeviceIoControlFile(iptHandle,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &ioStatusBlock,
                                       IOCTL_IPT_REQUEST,
                                       &inputBuffer,
                                       sizeof(inputBuffer),
                                       &outputBuffer,
                                       sizeof(outputBuffer));
        if (NT_SUCCESS(status))
        {
            *TraceStopRangeEntered = outputBuffer.QueryThreadTraceStopRangeEntered.TraceStopRangeEntered;
        }
        NtClose(iptHandle);
    }
    return status;
}
