using System;
using System.Buffers;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;

namespace FitbitDesktopOSC
{
    public class MemoryScanner : IDisposable
    {
        internal const int ProcessQueryInformation = 1024;
        internal const int MemCommit = 4096;
        internal const int PageReadWrite = 4;
        internal const int ProcessWmRead = 16;

        private static readonly int MemBasicInfoSize = Marshal.SizeOf(default(MemoryBasicInformation));

        public readonly IntPtr ProcessMinAddress;
        public readonly long ProcessMinAddressL;

        public readonly IntPtr ProcessMaxAddress;
        public readonly long ProcessMaxAddressL;

        public readonly long ProcessAddressCount;

        private readonly int processId;
        private readonly IntPtr processHandle;

        private readonly List<IntPtr> targetPtrs = new();

        private bool disposedValue;

        public MemoryScanner(int processId)
        {
            this.processId = processId;

            GetSystemInfo(out SystemInfo sysInfo);

            ProcessMinAddress = sysInfo.MinimumApplicationAddress;
            ProcessMinAddressL = (long)sysInfo.MinimumApplicationAddress;

            ProcessMaxAddress = sysInfo.MaximumApplicationAddress;
            ProcessMaxAddressL = (long)sysInfo.MaximumApplicationAddress;

            ProcessAddressCount = ProcessMaxAddressL - ProcessMinAddressL;

            processHandle = OpenProcess(ProcessQueryInformation | ProcessWmRead, false, (uint)processId);
            if (processHandle == IntPtr.Zero)
            {
                throw new InvalidOperationException($"The process could not be hooked. Error code: {Marshal.GetLastWin32Error()}");
            }
        }

        public MemoryScanner(Process process) : this(process.Id)
        {
        }

        public MemoryScanner(string processName) : this(Process.GetProcessesByName(processName)[0])
        {
        }

        public void DumpMemory(string file)
        {
            using var sw = new StreamWriter(file);

            var currentAddress = ProcessMinAddress;
            var currentAddressL = ProcessMinAddressL;

            while (currentAddressL < ProcessMaxAddressL)
            {
                if (VirtualQueryEx(processHandle, currentAddress, out var memBasicInfo, MemBasicInfoSize) <= 0)
                {
                    throw new Exception($"Failed to find process memory region at {currentAddress}. Error code: {Marshal.GetLastWin32Error()}");
                }
                var regionSize = memBasicInfo.RegionSize.ToUInt64();

                // If this memory chunk is accessible
                if (memBasicInfo.Protect == PageReadWrite && memBasicInfo.State == MemCommit && regionSize > 0)
                {
                    var buffer = new byte[regionSize];
                    if (!ReadProcessMemory(processHandle, memBasicInfo.BaseAddress, buffer, (uint)regionSize, out var bytesRead))
                    {
                        throw new Exception($"Failed to read process memory at {memBasicInfo.BaseAddress}. Error code: {Marshal.GetLastWin32Error()}");
                    }

                    for (var i = 0; i < bytesRead; i++)
                        sw.Write((char)buffer[i]);
                }

                // Move to the next memory chunk
                currentAddressL += (long)regionSize;
                currentAddress = new IntPtr(currentAddressL);

                var currentValue = currentAddressL - ProcessMinAddressL;
                Console.WriteLine($"{currentValue}/{ProcessAddressCount} ({currentValue / (double)ProcessAddressCount:0.00%})");
            }
        }

        public void ScanMemory(byte[] targetValue, Action<MemorySearchProgress>? progressCallback = null)
        {
            var currentAddress = ProcessMinAddress;
            var currentAddressL = ProcessMinAddressL;

            // Search for regions
            var regionsInformation = new List<MemoryBasicInformation>();
            while (currentAddressL < ProcessMaxAddressL)
            {
                if (VirtualQueryEx(processHandle, currentAddress, out var memBasicInfo, MemBasicInfoSize) <= 0)
                {
                    throw new Exception($"Failed to find process memory region at {currentAddress}. Error code: {Marshal.GetLastWin32Error()}");
                }
                var regionSize = memBasicInfo.RegionSize.ToUInt64();

                // If this memory chunk is accessible
                if (memBasicInfo.Protect == PageReadWrite && memBasicInfo.State == MemCommit && regionSize > 0)
                {
                    regionsInformation.Add(memBasicInfo);
                }

                // Move to the next memory chunk
                currentAddressL += (long)regionSize;
                currentAddress = new IntPtr(currentAddressL);

                progressCallback?.Invoke(new MemorySearchProgress()
                {
                    Current = currentAddressL - ProcessMinAddressL,
                    Total = ProcessAddressCount
                });
            }

            // Asynchronously search each region
            var regionSearchTasks = new List<Task>(regionsInformation.Count);
            foreach (var region in regionsInformation)
            {
                regionSearchTasks.Add(Task.Run(() => { ScanMemoryRegion(region, targetValue); }));
            }
            Task.WaitAll(regionSearchTasks.ToArray());
        }

        public void ScanMemory(int targetValue, Action<MemorySearchProgress>? progressCallback = null)
        {
            ScanMemory(BitConverter.GetBytes(targetValue), progressCallback);
        }

        /// <summary>
        /// Adds matching <seealso cref="IntPtr"/>s to the <seealso cref="List{T}"/> named <see cref="targetPtrs"/>.
        /// </summary>
        /// <param name="region">The memory region to search.</param>
        /// <param name="targetValue">The target pattern to match.</param>
        private void ScanMemoryRegion(MemoryBasicInformation region, byte[] targetValue)
        {
            var regionSize = region.RegionSize.ToUInt64();

            var buffer = ArrayPool<byte>.Shared.Rent((int)regionSize);
            try
            {
                if (!ReadProcessMemory(processHandle, region.BaseAddress, buffer, (uint)regionSize, out var bytesRead))
                {
                    throw new Exception($"Failed to read process memory at {region.BaseAddress}. Error code: {Marshal.GetLastWin32Error()}");
                }

                var offset = 0;
                // Only search until the bytes cannot possibly match
                while (offset < bytesRead - targetValue.Length)
                {
                    var index = IndexOfBytes(buffer, targetValue, startIndex: offset, length: (int)(bytesRead - offset));
                    if (index < 0)
                    {
                        // Can't find any match, give up
                        break;
                    }

                    AddTargetPointer(IntPtr.Add(region.BaseAddress, index));

                    offset = index + 1;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        private void AddTargetPointer(IntPtr pointer)
        {
            lock (targetPtrs)
            {
                targetPtrs.Add(pointer);
            }
        }

        private void RemoveTargetPointer(IntPtr pointer)
        {
            lock (targetPtrs)
            {
                targetPtrs.Remove(pointer);
            }
        }

        private void RemoveTargetPointerAt(int index)
        {
            lock (targetPtrs)
            {
                targetPtrs.RemoveAt(index);
            }
        }

        private int IndexOfBytes(byte[] source, byte[] pattern, int startIndex = 0, int length = 0)
        {
            var matchLength = 0;
            for (var i = startIndex; i < startIndex + length; i++ )
            {
                if (source[i] == pattern[matchLength])
                {
                    matchLength++;
                }
                else
                {
                    matchLength = 0;
                }

                if (matchLength >= pattern.Length)
                {
                    return i - (matchLength - 1);
                }
            }

            return -1;
        }

        public IntPtr[] GetTargetPointers()
        {
            return targetPtrs.ToArray();
        }

        private static void CloseHandleOrThrow(IntPtr processHandle, Exception? innerException = null)
        {
            if (CloseHandle(processHandle) == 0)
            {
                throw new Exception($"Unable to close the process handle {processHandle}. Error code: {Marshal.GetLastWin32Error()}", innerException);
            }
        }

        public void Dispose()
        {
            if (!disposedValue)
            {
                targetPtrs.Clear();
                CloseHandleOrThrow(processHandle);
                disposedValue = true;
            }
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Opens an existing local process object.
        /// </summary>
        /// <param name="dwDesiredAccess">The access to the process object. This access right is checked against the security descriptor for the process. This parameter can be one or more of the process access rights.</param>
        /// <param name="bInheritHandle">If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.</param>
        /// <param name="dwProcessId">The identifier of the local process to be opened.</param>
        /// <returns>If the function succeeds, the return value is an open handle to the specified process. If the function fails, the return value is NULL.</returns>
        [DllImport("kernel32.dll")]
        internal static extern IntPtr OpenProcess([In] uint dwDesiredAccess, [In] bool bInheritHandle, [In] uint dwProcessId);

        /// <summary>
        /// Closes an open object handle.
        /// </summary>
        /// <param name="hObject">A valid handle to an open object.</param>
        /// <returns>If the function succeeds, the return value is nonzero. If the function fails, the return value is 0 (zero).</returns>
        [DllImport("kernel32.dll")]
        internal static extern int CloseHandle([In] IntPtr hObject);

        /// <summary>
        /// Reads memory.
        /// </summary>
        /// <param name="hProcess">The handle to the process.</param>
        /// <param name="lpBaseAddress">The starting address to read.</param>
        /// <param name="buffer">The byte array to hold the results.</param>
        /// <param name="size">The number of bytes to read.</param>
        /// <param name="lpNumberOfBytesRead">The number of bytes read.</param>
        /// <returns>If the function succeeds, the return value is nonzero. If the function fails, the return value is 0 (zero).</returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool ReadProcessMemory([In] IntPtr hProcess, [In] IntPtr lpBaseAddress, [Out] byte[] lpBuffer, [In] uint dwSize, [Out] out uint lpNumberOfBytesRead);

        /// <summary>
        /// Retrieves information about the current system.
        /// </summary>
        /// <param name="lpSystemInfo">A pointer to a SystemInfo structure that receives the information.</param>
        [DllImport("kernel32.dll")]
        internal static extern void GetSystemInfo([Out] out SystemInfo lpSystemInfo);

        /// <summary>
        /// Retrieves information about a range of pages within the virtual address space of a specified process.
        /// </summary>
        /// <param name="hProcess">A handle to the process whose memory information is queried.</param>
        /// <param name="lpAddress">A pointer to the base address of the region of pages to be queried.</param>
        /// <param name="lpBuffer">A pointer to a MemoryBasicInformation structure in which information about the specified page range is returned.</param>
        /// <param name="dwLength">The size of the buffer pointed to by the lpBuffer parameter, in bytes.</param>
        /// <returns>The return value is the actual number of bytes returned in the information buffer. If the function fails, the return value is zero.</returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int VirtualQueryEx([In] IntPtr hProcess, [In, Optional] IntPtr lpAddress, [Out] out MemoryBasicInformation lpBuffer, [In] int dwLength);

        public enum ProcessorArchitecture : ushort
        {
            X86 = 0,
            X64 = 9,
            Arm = 5,
            Itanium = 6,
            Arm64 = 12,
            Unknown = 0xFFFF
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SystemInfo
        {
            public ProcessorArchitecture ProcessorArchitecture;
            public uint PageSize;
            public IntPtr MinimumApplicationAddress;
            public IntPtr MaximumApplicationAddress;
            public UIntPtr ActiveProcessorMask;
            public uint NumberOfProcessors;
            public uint ProcessorType;
            public uint AllocationGranularity;
            public ushort ProcessorLevel;
            public ushort ProcessorRevision;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MemoryBasicInformation
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public UIntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        public struct MemorySearchProgress
        {
            public long Current;
            public long Total;
        }
    }
}
