using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

public class DLLFromMemory : IDisposable
{
    // Token: 0x1700000E RID: 14
    // (get) Token: 0x060000A1 RID: 161 RVA: 0x0005B358 File Offset: 0x00059558
    // (set) Token: 0x060000A2 RID: 162 RVA: 0x0005B360 File Offset: 0x00059560
    public bool Disposed { get; private set; }

    // Token: 0x1700000F RID: 15
    // (get) Token: 0x060000A3 RID: 163 RVA: 0x0005B369 File Offset: 0x00059569
    // (set) Token: 0x060000A4 RID: 164 RVA: 0x0005B371 File Offset: 0x00059571
    public bool IsDll { get; private set; }

    // Token: 0x060000A5 RID: 165 RVA: 0x0005B37C File Offset: 0x0005957C
    public DLLFromMemory(byte[] data)
    {
        this.Disposed = false;
        bool flag = data == null;
        if (flag)
        {
            throw new ArgumentNullException("data");
        }
        this.MemoryLoadLibrary(data);
    }

    // Token: 0x060000A6 RID: 166 RVA: 0x0005B3E8 File Offset: 0x000595E8
    ~DLLFromMemory()
    {
        this.Dispose();
    }

    // Token: 0x060000A7 RID: 167 RVA: 0x0005B418 File Offset: 0x00059618
    public TDelegate GetDelegateFromFuncName<TDelegate>(string funcName) where TDelegate : class
    {
        bool flag = !typeof(Delegate).IsAssignableFrom(typeof(TDelegate));
        if (flag)
        {
            throw new ArgumentException(typeof(TDelegate).Name + " is not a delegate");
        }
        TDelegate tdelegate = Marshal.GetDelegateForFunctionPointer(this.GetPtrFromFuncName(funcName), typeof(TDelegate)) as TDelegate;
        bool flag2 = tdelegate == null;
        if (flag2)
        {
            throw new DLLFromMemory.DllException("Unable to get managed delegate");
        }
        return tdelegate;
    }

    // Token: 0x060000A8 RID: 168 RVA: 0x0005B4A4 File Offset: 0x000596A4
    public Delegate GetDelegateFromFuncName(string funcName, Type delegateType)
    {
        bool flag = delegateType == null;
        if (flag)
        {
            throw new ArgumentNullException("delegateType");
        }
        bool flag2 = !typeof(Delegate).IsAssignableFrom(delegateType);
        if (flag2)
        {
            throw new ArgumentException(delegateType.Name + " is not a delegate");
        }
        Delegate delegateForFunctionPointer = Marshal.GetDelegateForFunctionPointer(this.GetPtrFromFuncName(funcName), delegateType);
        bool flag3 = delegateForFunctionPointer == null;
        if (flag3)
        {
            throw new DLLFromMemory.DllException("Unable to get managed delegate");
        }
        return delegateForFunctionPointer;
    }

    // Token: 0x060000A9 RID: 169 RVA: 0x0005B520 File Offset: 0x00059720
    private IntPtr GetPtrFromFuncName(string funcName)
    {
        bool disposed = this.Disposed;
        if (disposed)
        {
            throw new ObjectDisposedException("DLLFromMemory");
        }
        bool flag = string.IsNullOrEmpty(funcName);
        if (flag)
        {
            throw new ArgumentException("funcName");
        }
        bool flag2 = !this.IsDll;
        if (flag2)
        {
            throw new InvalidOperationException("Loaded Module is not a DLL");
        }
        bool flag3 = !this._initialized;
        if (flag3)
        {
            throw new InvalidOperationException("Dll is not initialized");
        }
        IntPtr intPtr = DLLFromMemory.PtrAdd(this.pNTHeaders, 24 + (DLLFromMemory.Is64BitProcess ? 112 : 96));
        DLLFromMemory.IMAGE_DATA_DIRECTORY image_DATA_DIRECTORY = DLLFromMemory.PtrRead<DLLFromMemory.IMAGE_DATA_DIRECTORY>(intPtr);
        bool flag4 = image_DATA_DIRECTORY.Size == 0U;
        if (flag4)
        {
            throw new DLLFromMemory.DllException("Dll has no export table");
        }
        IntPtr intPtr2 = DLLFromMemory.PtrAdd(this.pCode, image_DATA_DIRECTORY.VirtualAddress);
        DLLFromMemory.IMAGE_EXPORT_DIRECTORY image_EXPORT_DIRECTORY = DLLFromMemory.PtrRead<DLLFromMemory.IMAGE_EXPORT_DIRECTORY>(intPtr2);
        bool flag5 = image_EXPORT_DIRECTORY.NumberOfFunctions == 0U || image_EXPORT_DIRECTORY.NumberOfNames == 0U;
        if (flag5)
        {
            throw new DLLFromMemory.DllException("Dll exports no functions");
        }
        IntPtr intPtr3 = DLLFromMemory.PtrAdd(this.pCode, image_EXPORT_DIRECTORY.AddressOfNames);
        IntPtr intPtr4 = DLLFromMemory.PtrAdd(this.pCode, image_EXPORT_DIRECTORY.AddressOfNameOrdinals);
        int num = 0;
        while ((long)num < (long)((ulong)image_EXPORT_DIRECTORY.NumberOfNames))
        {
            uint num2 = DLLFromMemory.PtrRead<uint>(intPtr3);
            ushort num3 = DLLFromMemory.PtrRead<ushort>(intPtr4);
            string text = Marshal.PtrToStringAnsi(DLLFromMemory.PtrAdd(this.pCode, num2));
            bool flag6 = text == funcName;
            if (flag6)
            {
                bool flag7 = (uint)num3 > image_EXPORT_DIRECTORY.NumberOfFunctions;
                if (flag7)
                {
                    throw new DLLFromMemory.DllException("Invalid function ordinal");
                }
                IntPtr intPtr5 = DLLFromMemory.PtrAdd(this.pCode, image_EXPORT_DIRECTORY.AddressOfFunctions + (uint)(num3 * 4));
                return DLLFromMemory.PtrAdd(this.pCode, DLLFromMemory.PtrRead<uint>(intPtr5));
            }
            else
            {
                num++;
                intPtr3 = DLLFromMemory.PtrAdd(intPtr3, 4);
                intPtr4 = DLLFromMemory.PtrAdd(intPtr4, 2);
            }
        }
        throw new DLLFromMemory.DllException("Dll exports no function named " + funcName);
    }

    // Token: 0x060000AA RID: 170 RVA: 0x0005B6FC File Offset: 0x000598FC
    public int MemoryCallEntryPoint()
    {
        bool disposed = this.Disposed;
        if (disposed)
        {
            throw new ObjectDisposedException("DLLFromMemory");
        }
        bool flag = this.IsDll || this._exeEntry == null || !this._isRelocated;
        if (flag)
        {
            throw new DLLFromMemory.DllException("Unable to call entry point. Is loaded module a dll?");
        }
        return this._exeEntry();
    }

    // Token: 0x060000AB RID: 171 RVA: 0x0005B75C File Offset: 0x0005995C
    private void MemoryLoadLibrary(byte[] data)
    {
        bool flag = data.Length < Marshal.SizeOf(typeof(DLLFromMemory.IMAGE_DOS_HEADER));
        if (flag)
        {
            throw new DLLFromMemory.DllException("Not a valid executable file");
        }
        DLLFromMemory.IMAGE_DOS_HEADER image_DOS_HEADER = DLLFromMemory.BytesReadStructAt<DLLFromMemory.IMAGE_DOS_HEADER>(data, 0);
        bool flag2 = image_DOS_HEADER.e_magic != 23117;
        if (flag2)
        {
            throw new BadImageFormatException("Not a valid executable file");
        }
        bool flag3 = data.Length < image_DOS_HEADER.e_lfanew + Marshal.SizeOf(typeof(DLLFromMemory.IMAGE_NT_HEADERS));
        if (flag3)
        {
            throw new DLLFromMemory.DllException("Not a valid executable file");
        }
        DLLFromMemory.IMAGE_NT_HEADERS image_NT_HEADERS = DLLFromMemory.BytesReadStructAt<DLLFromMemory.IMAGE_NT_HEADERS>(data, image_DOS_HEADER.e_lfanew);
        bool flag4 = image_NT_HEADERS.Signature != 17744U;
        if (flag4)
        {
            throw new BadImageFormatException("Not a valid PE file");
        }
        bool flag5 = (uint)image_NT_HEADERS.FileHeader.Machine != DLLFromMemory.GetMachineType();
        if (flag5)
        {
            throw new BadImageFormatException("Machine type doesn't fit (i386 vs. AMD64)");
        }
        bool flag6 = (image_NT_HEADERS.OptionalHeader.SectionAlignment & 1U) > 0U;
        if (flag6)
        {
            throw new BadImageFormatException("Wrong section alignment");
        }
        bool flag7 = image_NT_HEADERS.OptionalHeader.AddressOfEntryPoint == 0U;
        if (flag7)
        {
            throw new DLLFromMemory.DllException("Module has no entry point");
        }
        DLLFromMemory.SYSTEM_INFO system_INFO;
        DLLFromMemory.Win.GetNativeSystemInfo(out system_INFO);
        uint num = 0U;
        int num2 = DLLFromMemory.Win.IMAGE_FIRST_SECTION(image_DOS_HEADER.e_lfanew, image_NT_HEADERS.FileHeader.SizeOfOptionalHeader);
        int num3 = 0;
        while (num3 != (int)image_NT_HEADERS.FileHeader.NumberOfSections)
        {
            DLLFromMemory.IMAGE_SECTION_HEADER image_SECTION_HEADER = DLLFromMemory.BytesReadStructAt<DLLFromMemory.IMAGE_SECTION_HEADER>(data, num2);
            uint num4 = image_SECTION_HEADER.VirtualAddress + ((image_SECTION_HEADER.SizeOfRawData > 0U) ? image_SECTION_HEADER.SizeOfRawData : image_NT_HEADERS.OptionalHeader.SectionAlignment);
            bool flag8 = num4 > num;
            if (flag8)
            {
                num = num4;
            }
            num3++;
            num2 += 40;
        }
        uint num5 = DLLFromMemory.AlignValueUp(image_NT_HEADERS.OptionalHeader.SizeOfImage, system_INFO.dwPageSize);
        uint num6 = DLLFromMemory.AlignValueUp(num, system_INFO.dwPageSize);
        bool flag9 = num5 != num6;
        if (flag9)
        {
            throw new BadImageFormatException("Wrong section alignment");
        }
        bool is64BitProcess = DLLFromMemory.Is64BitProcess;
        IntPtr intPtr;
        if (is64BitProcess)
        {
            intPtr = (IntPtr)((long)image_NT_HEADERS.OptionalHeader.ImageBaseLong);
        }
        else
        {
            intPtr = (IntPtr)((int)(image_NT_HEADERS.OptionalHeader.ImageBaseLong >> 32));
        }
        this.pCode = DLLFromMemory.Win.VirtualAlloc(intPtr, (UIntPtr)image_NT_HEADERS.OptionalHeader.SizeOfImage, (DLLFromMemory.AllocationType)12288U, DLLFromMemory.MemoryProtection.READWRITE);
        bool flag10 = this.pCode == IntPtr.Zero;
        if (flag10)
        {
            this.pCode = DLLFromMemory.Win.VirtualAlloc(IntPtr.Zero, (UIntPtr)image_NT_HEADERS.OptionalHeader.SizeOfImage, (DLLFromMemory.AllocationType)12288U, DLLFromMemory.MemoryProtection.READWRITE);
        }
        bool flag11 = this.pCode == IntPtr.Zero;
        if (flag11)
        {
            throw new DLLFromMemory.DllException("Out of Memory");
        }
        bool flag12 = DLLFromMemory.Is64BitProcess && DLLFromMemory.PtrSpanBoundary(this.pCode, num5, 32);
        if (flag12)
        {
            List<IntPtr> list = new List<IntPtr>();
            while (DLLFromMemory.PtrSpanBoundary(this.pCode, num5, 32))
            {
                list.Add(this.pCode);
                this.pCode = DLLFromMemory.Win.VirtualAlloc(IntPtr.Zero, (UIntPtr)num5, (DLLFromMemory.AllocationType)12288U, DLLFromMemory.MemoryProtection.READWRITE);
                bool flag13 = this.pCode == IntPtr.Zero;
                if (flag13)
                {
                    break;
                }
            }
            foreach (IntPtr intPtr2 in list)
            {
                DLLFromMemory.Win.VirtualFree(intPtr2, IntPtr.Zero, DLLFromMemory.AllocationType.RELEASE);
            }
            bool flag14 = this.pCode == IntPtr.Zero;
            if (flag14)
            {
                throw new DLLFromMemory.DllException("Out of Memory");
            }
        }
        IntPtr intPtr3 = DLLFromMemory.Win.VirtualAlloc(this.pCode, (UIntPtr)image_NT_HEADERS.OptionalHeader.SizeOfHeaders, DLLFromMemory.AllocationType.COMMIT, DLLFromMemory.MemoryProtection.READWRITE);
        bool flag15 = intPtr3 == IntPtr.Zero;
        if (flag15)
        {
            throw new DLLFromMemory.DllException("Out of Memory");
        }
        Marshal.Copy(data, 0, intPtr3, (int)image_NT_HEADERS.OptionalHeader.SizeOfHeaders);
        this.pNTHeaders = DLLFromMemory.PtrAdd(intPtr3, image_DOS_HEADER.e_lfanew);
        IntPtr intPtr4 = DLLFromMemory.PtrSub(this.pCode, intPtr);
        bool flag16 = intPtr4 != IntPtr.Zero;
        if (flag16)
        {
            Marshal.OffsetOf(typeof(DLLFromMemory.IMAGE_NT_HEADERS), "OptionalHeader");
            Marshal.OffsetOf(typeof(DLLFromMemory.IMAGE_OPTIONAL_HEADER), "ImageBaseLong");
            IntPtr intPtr5 = DLLFromMemory.PtrAdd(this.pNTHeaders, 24 + (DLLFromMemory.Is64BitProcess ? 24 : 28));
            DLLFromMemory.PtrWrite<IntPtr>(intPtr5, this.pCode);
        }
        DLLFromMemory.CopySections(ref image_NT_HEADERS, this.pCode, this.pNTHeaders, data);
        this._isRelocated = !(intPtr4 != IntPtr.Zero) || DLLFromMemory.PerformBaseRelocation(ref image_NT_HEADERS, this.pCode, intPtr4);
        this.ImportModules = DLLFromMemory.BuildImportTable(ref image_NT_HEADERS, this.pCode);
        DLLFromMemory.FinalizeSections(ref image_NT_HEADERS, this.pCode, this.pNTHeaders, system_INFO.dwPageSize);
        DLLFromMemory.ExecuteTLS(ref image_NT_HEADERS, this.pCode, this.pNTHeaders);
        this.IsDll = (image_NT_HEADERS.FileHeader.Characteristics & 8192) > 0;
        bool flag17 = image_NT_HEADERS.OptionalHeader.AddressOfEntryPoint > 0U;
        if (flag17)
        {
            bool isDll = this.IsDll;
            if (isDll)
            {
                IntPtr intPtr6 = DLLFromMemory.PtrAdd(this.pCode, image_NT_HEADERS.OptionalHeader.AddressOfEntryPoint);
                this._dllEntry = (DLLFromMemory.DllEntryDelegate)Marshal.GetDelegateForFunctionPointer(intPtr6, typeof(DLLFromMemory.DllEntryDelegate));
                this._initialized = this._dllEntry != null && this._dllEntry(this.pCode, DLLFromMemory.DllReason.DLL_PROCESS_ATTACH, IntPtr.Zero);
                bool flag18 = !this._initialized;
                if (flag18)
                {
                    throw new DLLFromMemory.DllException("Can't attach DLL to process");
                }
            }
            else
            {
                IntPtr intPtr7 = DLLFromMemory.PtrAdd(this.pCode, image_NT_HEADERS.OptionalHeader.AddressOfEntryPoint);
                this._exeEntry = (DLLFromMemory.ExeEntryDelegate)Marshal.GetDelegateForFunctionPointer(intPtr7, typeof(DLLFromMemory.ExeEntryDelegate));
            }
        }
    }

    // Token: 0x060000AC RID: 172 RVA: 0x0005BD40 File Offset: 0x00059F40
    private static void CopySections(ref DLLFromMemory.IMAGE_NT_HEADERS OrgNTHeaders, IntPtr pCode, IntPtr pNTHeaders, byte[] data)
    {
        IntPtr intPtr = DLLFromMemory.Win.IMAGE_FIRST_SECTION(pNTHeaders, OrgNTHeaders.FileHeader.SizeOfOptionalHeader);
        int i = 0;
        while (i < (int)OrgNTHeaders.FileHeader.NumberOfSections)
        {
            DLLFromMemory.IMAGE_SECTION_HEADER image_SECTION_HEADER = DLLFromMemory.PtrRead<DLLFromMemory.IMAGE_SECTION_HEADER>(intPtr);
            bool flag = image_SECTION_HEADER.SizeOfRawData == 0U;
            if (flag)
            {
                uint sectionAlignment = OrgNTHeaders.OptionalHeader.SectionAlignment;
                bool flag2 = sectionAlignment > 0U;
                if (flag2)
                {
                    IntPtr intPtr2 = DLLFromMemory.Win.VirtualAlloc(DLLFromMemory.PtrAdd(pCode, image_SECTION_HEADER.VirtualAddress), (UIntPtr)sectionAlignment, DLLFromMemory.AllocationType.COMMIT, DLLFromMemory.MemoryProtection.READWRITE);
                    bool flag3 = intPtr2 == IntPtr.Zero;
                    if (flag3)
                    {
                        throw new DLLFromMemory.DllException("Unable to allocate memory");
                    }
                    intPtr2 = DLLFromMemory.PtrAdd(pCode, image_SECTION_HEADER.VirtualAddress);
                    DLLFromMemory.PtrWrite<uint>(DLLFromMemory.PtrAdd(intPtr, 8), (uint)(long)intPtr2);
                    DLLFromMemory.Win.MemSet(intPtr2, 0, (UIntPtr)sectionAlignment);
                }
            }
            else
            {
                IntPtr intPtr3 = DLLFromMemory.Win.VirtualAlloc(DLLFromMemory.PtrAdd(pCode, image_SECTION_HEADER.VirtualAddress), (UIntPtr)image_SECTION_HEADER.SizeOfRawData, DLLFromMemory.AllocationType.COMMIT, DLLFromMemory.MemoryProtection.READWRITE);
                bool flag4 = intPtr3 == IntPtr.Zero;
                if (flag4)
                {
                    throw new DLLFromMemory.DllException("Out of memory");
                }
                intPtr3 = DLLFromMemory.PtrAdd(pCode, image_SECTION_HEADER.VirtualAddress);
                checked
                {
                    Marshal.Copy(data, (int)image_SECTION_HEADER.PointerToRawData, intPtr3, (int)image_SECTION_HEADER.SizeOfRawData);
                }
                DLLFromMemory.PtrWrite<uint>(DLLFromMemory.PtrAdd(intPtr, 8), (uint)(long)intPtr3);
            }
            i++;
            intPtr = DLLFromMemory.PtrAdd(intPtr, 40);
        }
    }

    // Token: 0x060000AD RID: 173 RVA: 0x0005BEB0 File Offset: 0x0005A0B0
    private static bool PerformBaseRelocation(ref DLLFromMemory.IMAGE_NT_HEADERS OrgNTHeaders, IntPtr pCode, IntPtr delta)
    {
        bool flag = OrgNTHeaders.OptionalHeader.BaseRelocationTable.Size == 0U;
        bool flag2;
        if (flag)
        {
            flag2 = delta == IntPtr.Zero;
        }
        else
        {
            IntPtr intPtr = DLLFromMemory.PtrAdd(pCode, OrgNTHeaders.OptionalHeader.BaseRelocationTable.VirtualAddress);
            for (; ; )
            {
                DLLFromMemory.IMAGE_BASE_RELOCATION image_BASE_RELOCATION = DLLFromMemory.PtrRead<DLLFromMemory.IMAGE_BASE_RELOCATION>(intPtr);
                bool flag3 = image_BASE_RELOCATION.VirtualAdress == 0U;
                if (flag3)
                {
                    break;
                }
                IntPtr intPtr2 = DLLFromMemory.PtrAdd(pCode, image_BASE_RELOCATION.VirtualAdress);
                IntPtr intPtr3 = DLLFromMemory.PtrAdd(intPtr, 8);
                uint num = (image_BASE_RELOCATION.SizeOfBlock - 8U) / 2U;
                uint num2 = 0U;
                while (num2 != num)
                {
                    ushort num3 = (ushort)Marshal.PtrToStructure(intPtr3, typeof(ushort));
                    DLLFromMemory.BasedRelocationType basedRelocationType = (DLLFromMemory.BasedRelocationType)(num3 >> 12);
                    int num4 = (int)(num3 & 4095);
                    IntPtr intPtr4 = DLLFromMemory.PtrAdd(intPtr2, num4);
                    DLLFromMemory.BasedRelocationType basedRelocationType2 = basedRelocationType;
                    DLLFromMemory.BasedRelocationType basedRelocationType3 = basedRelocationType2;
                    if (basedRelocationType3 != DLLFromMemory.BasedRelocationType.IMAGE_REL_BASED_ABSOLUTE)
                    {
                        if (basedRelocationType3 != DLLFromMemory.BasedRelocationType.IMAGE_REL_BASED_HIGHLOW)
                        {
                            if (basedRelocationType3 == DLLFromMemory.BasedRelocationType.IMAGE_REL_BASED_DIR64)
                            {
                                long num5 = (long)Marshal.PtrToStructure(intPtr4, typeof(long));
                                num5 += (long)delta;
                                Marshal.StructureToPtr<long>(num5, intPtr4, false);
                            }
                        }
                        else
                        {
                            int num6 = (int)Marshal.PtrToStructure(intPtr4, typeof(int));
                            num6 += (int)delta;
                            Marshal.StructureToPtr<int>(num6, intPtr4, false);
                        }
                    }
                    num2 += 1U;
                    intPtr3 = DLLFromMemory.PtrAdd(intPtr3, 2);
                }
                intPtr = DLLFromMemory.PtrAdd(intPtr, image_BASE_RELOCATION.SizeOfBlock);
            }
            flag2 = true;
        }
        return flag2;
    }

    // Token: 0x060000AE RID: 174 RVA: 0x0005C038 File Offset: 0x0005A238
    private static IntPtr[] BuildImportTable(ref DLLFromMemory.IMAGE_NT_HEADERS OrgNTHeaders, IntPtr pCode)
    {
        List<IntPtr> list = new List<IntPtr>();
        uint num = OrgNTHeaders.OptionalHeader.ImportTable.Size / 20U;
        IntPtr intPtr = DLLFromMemory.PtrAdd(pCode, OrgNTHeaders.OptionalHeader.ImportTable.VirtualAddress);
        uint num2 = 0U;
        while (num2 != num)
        {
            DLLFromMemory.IMAGE_IMPORT_DESCRIPTOR image_IMPORT_DESCRIPTOR = DLLFromMemory.PtrRead<DLLFromMemory.IMAGE_IMPORT_DESCRIPTOR>(intPtr);
            bool flag = image_IMPORT_DESCRIPTOR.Name == 0U;
            if (flag)
            {
                break;
            }
            IntPtr intPtr2 = DLLFromMemory.Win.LoadLibrary(DLLFromMemory.PtrAdd(pCode, image_IMPORT_DESCRIPTOR.Name));
            bool flag2 = DLLFromMemory.PtrIsInvalidHandle(intPtr2);
            if (flag2)
            {
                foreach (IntPtr intPtr3 in list)
                {
                    DLLFromMemory.Win.FreeLibrary(intPtr3);
                }
                list.Clear();
                throw new DLLFromMemory.DllException("Can't load libary " + Marshal.PtrToStringAnsi(DLLFromMemory.PtrAdd(pCode, image_IMPORT_DESCRIPTOR.Name)));
            }
            list.Add(intPtr2);
            bool flag3 = image_IMPORT_DESCRIPTOR.OriginalFirstThunk > 0U;
            IntPtr intPtr4;
            IntPtr intPtr5;
            if (flag3)
            {
                intPtr4 = DLLFromMemory.PtrAdd(pCode, image_IMPORT_DESCRIPTOR.OriginalFirstThunk);
                intPtr5 = DLLFromMemory.PtrAdd(pCode, image_IMPORT_DESCRIPTOR.FirstThunk);
            }
            else
            {
                intPtr4 = DLLFromMemory.PtrAdd(pCode, image_IMPORT_DESCRIPTOR.FirstThunk);
                intPtr5 = DLLFromMemory.PtrAdd(pCode, image_IMPORT_DESCRIPTOR.FirstThunk);
            }
            int size = IntPtr.Size;
            for (; ; )
            {
                IntPtr intPtr6 = DLLFromMemory.PtrRead<IntPtr>(intPtr4);
                bool flag4 = intPtr6 == IntPtr.Zero;
                if (flag4)
                {
                    break;
                }
                bool flag5 = DLLFromMemory.Win.IMAGE_SNAP_BY_ORDINAL(intPtr6);
                IntPtr intPtr7;
                if (flag5)
                {
                    intPtr7 = DLLFromMemory.Win.GetProcAddress(intPtr2, DLLFromMemory.Win.IMAGE_ORDINAL(intPtr6));
                }
                else
                {
                    intPtr7 = DLLFromMemory.Win.GetProcAddress(intPtr2, DLLFromMemory.PtrAdd(DLLFromMemory.PtrAdd(pCode, intPtr6), 2));
                }
                bool flag6 = intPtr7 == IntPtr.Zero;
                if (flag6)
                {
                    goto Block_7;
                }
                DLLFromMemory.PtrWrite<IntPtr>(intPtr5, intPtr7);
                intPtr4 = DLLFromMemory.PtrAdd(intPtr4, size);
                intPtr5 = DLLFromMemory.PtrAdd(intPtr5, size);
            }
            num2 += 1U;
            intPtr = DLLFromMemory.PtrAdd(intPtr, 20);
            continue;
        Block_7:
            throw new DLLFromMemory.DllException("Can't get adress for imported function");
        }
        return (list.Count > 0) ? list.ToArray() : null;
    }

    // Token: 0x060000AF RID: 175 RVA: 0x0005C268 File Offset: 0x0005A468
    private static void FinalizeSections(ref DLLFromMemory.IMAGE_NT_HEADERS OrgNTHeaders, IntPtr pCode, IntPtr pNTHeaders, uint PageSize)
    {
        UIntPtr uintPtr = (DLLFromMemory.Is64BitProcess ? ((UIntPtr)((ulong)(pCode.ToInt64() & -4294967296L))) : UIntPtr.Zero);
        IntPtr intPtr = DLLFromMemory.Win.IMAGE_FIRST_SECTION(pNTHeaders, OrgNTHeaders.FileHeader.SizeOfOptionalHeader);
        DLLFromMemory.IMAGE_SECTION_HEADER image_SECTION_HEADER = DLLFromMemory.PtrRead<DLLFromMemory.IMAGE_SECTION_HEADER>(intPtr);
        DLLFromMemory.SectionFinalizeData sectionFinalizeData = default(DLLFromMemory.SectionFinalizeData);
        sectionFinalizeData.Address = DLLFromMemory.PtrBitOr(DLLFromMemory.PtrAdd((IntPtr)0, image_SECTION_HEADER.PhysicalAddress), uintPtr);
        sectionFinalizeData.AlignedAddress = DLLFromMemory.PtrAlignDown(sectionFinalizeData.Address, (UIntPtr)PageSize);
        sectionFinalizeData.Size = DLLFromMemory.GetRealSectionSize(ref image_SECTION_HEADER, ref OrgNTHeaders);
        sectionFinalizeData.Characteristics = image_SECTION_HEADER.Characteristics;
        sectionFinalizeData.Last = false;
        intPtr = DLLFromMemory.PtrAdd(intPtr, 40);
        int i = 1;
        while (i < (int)OrgNTHeaders.FileHeader.NumberOfSections)
        {
            image_SECTION_HEADER = DLLFromMemory.PtrRead<DLLFromMemory.IMAGE_SECTION_HEADER>(intPtr);
            IntPtr intPtr2 = DLLFromMemory.PtrBitOr(DLLFromMemory.PtrAdd((IntPtr)0, image_SECTION_HEADER.PhysicalAddress), uintPtr);
            IntPtr intPtr3 = DLLFromMemory.PtrAlignDown(intPtr2, (UIntPtr)PageSize);
            IntPtr realSectionSize = DLLFromMemory.GetRealSectionSize(ref image_SECTION_HEADER, ref OrgNTHeaders);
            ulong num = (ulong)DLLFromMemory.PtrAdd(sectionFinalizeData.Address, sectionFinalizeData.Size).ToInt64();
            ulong num2 = (ulong)(long)intPtr3;
            bool flag = sectionFinalizeData.AlignedAddress == intPtr3 || DLLFromMemory.PtrAdd(sectionFinalizeData.Address, sectionFinalizeData.Size).ToInt64() > (long)intPtr3;
            if (flag)
            {
                bool flag2 = (image_SECTION_HEADER.Characteristics & 33554432U) == 0U || (sectionFinalizeData.Characteristics & 33554432U) == 0U;
                if (flag2)
                {
                    sectionFinalizeData.Characteristics = (sectionFinalizeData.Characteristics | image_SECTION_HEADER.Characteristics) & 4261412863U;
                }
                else
                {
                    sectionFinalizeData.Characteristics |= image_SECTION_HEADER.Characteristics;
                }
                sectionFinalizeData.Size = DLLFromMemory.PtrSub(DLLFromMemory.PtrAdd(intPtr2, realSectionSize), sectionFinalizeData.Address);
            }
            else
            {
                DLLFromMemory.FinalizeSection(sectionFinalizeData, PageSize, OrgNTHeaders.OptionalHeader.SectionAlignment);
                sectionFinalizeData.Address = intPtr2;
                sectionFinalizeData.AlignedAddress = intPtr3;
                sectionFinalizeData.Size = realSectionSize;
                sectionFinalizeData.Characteristics = image_SECTION_HEADER.Characteristics;
            }
            i++;
            intPtr = DLLFromMemory.PtrAdd(intPtr, 40);
        }
        sectionFinalizeData.Last = true;
        DLLFromMemory.FinalizeSection(sectionFinalizeData, PageSize, OrgNTHeaders.OptionalHeader.SectionAlignment);
    }

    // Token: 0x060000B0 RID: 176 RVA: 0x0005C4B4 File Offset: 0x0005A6B4
    private static void FinalizeSection(DLLFromMemory.SectionFinalizeData SectionData, uint PageSize, uint SectionAlignment)
    {
        bool flag = SectionData.Size == IntPtr.Zero;
        if (!flag)
        {
            bool flag2 = (SectionData.Characteristics & 33554432U) > 0U;
            if (flag2)
            {
                bool flag3 = SectionData.Address == SectionData.AlignedAddress && (SectionData.Last || SectionAlignment == PageSize || SectionData.Size.ToInt64() % (long)((ulong)PageSize) == 0L);
                if (flag3)
                {
                    DLLFromMemory.Win.VirtualFree(SectionData.Address, SectionData.Size, DLLFromMemory.AllocationType.DECOMMIT);
                }
            }
            else
            {
                int num = (((SectionData.Characteristics & 1073741824U) != 0U) ? 1 : 0);
                int num2 = (((SectionData.Characteristics & 2147483648U) != 0U) ? 1 : 0);
                int num3 = (((SectionData.Characteristics & 536870912U) != 0U) ? 1 : 0);
                uint num4 = (uint)DLLFromMemory.ProtectionFlags[num3, num, num2];
                bool flag4 = (SectionData.Characteristics & 67108864U) > 0U;
                if (flag4)
                {
                    num4 |= 512U;
                }
                uint num5;
                bool flag5 = !DLLFromMemory.Win.VirtualProtect(SectionData.Address, SectionData.Size, num4, out num5);
                if (flag5)
                {
                    throw new DLLFromMemory.DllException("Error protecting memory page");
                }
            }
        }
    }

    // Token: 0x060000B1 RID: 177 RVA: 0x0005C5DC File Offset: 0x0005A7DC
    private static void ExecuteTLS(ref DLLFromMemory.IMAGE_NT_HEADERS OrgNTHeaders, IntPtr pCode, IntPtr pNTHeaders)
    {
        bool flag = OrgNTHeaders.OptionalHeader.TLSTable.VirtualAddress == 0U;
        if (!flag)
        {
            DLLFromMemory.IMAGE_TLS_DIRECTORY image_TLS_DIRECTORY = DLLFromMemory.PtrRead<DLLFromMemory.IMAGE_TLS_DIRECTORY>(DLLFromMemory.PtrAdd(pCode, OrgNTHeaders.OptionalHeader.TLSTable.VirtualAddress));
            IntPtr intPtr = image_TLS_DIRECTORY.AddressOfCallBacks;
            bool flag2 = intPtr != IntPtr.Zero;
            if (flag2)
            {
                IntPtr intPtr2;
                while ((intPtr2 = DLLFromMemory.PtrRead<IntPtr>(intPtr)) != IntPtr.Zero)
                {
                    DLLFromMemory.ImageTlsDelegate imageTlsDelegate = (DLLFromMemory.ImageTlsDelegate)Marshal.GetDelegateForFunctionPointer(intPtr2, typeof(DLLFromMemory.ImageTlsDelegate));
                    imageTlsDelegate(pCode, DLLFromMemory.DllReason.DLL_PROCESS_ATTACH, IntPtr.Zero);
                    intPtr = DLLFromMemory.PtrAdd(intPtr, IntPtr.Size);
                }
            }
        }
    }

    // Token: 0x17000010 RID: 16
    // (get) Token: 0x060000B2 RID: 178 RVA: 0x0005C68C File Offset: 0x0005A88C
    public static bool Is64BitProcess
    {
        get
        {
            return IntPtr.Size == 8;
        }
    }

    // Token: 0x060000B3 RID: 179 RVA: 0x0005C6A8 File Offset: 0x0005A8A8
    private static uint GetMachineType()
    {
        return (IntPtr.Size == 8) ? 34404U : 332U;
    }

    // Token: 0x060000B4 RID: 180 RVA: 0x0005C6D0 File Offset: 0x0005A8D0
    private static uint AlignValueUp(uint value, uint alignment)
    {
        return (value + alignment - 1U) & ~(alignment - 1U);
    }

    // Token: 0x060000B5 RID: 181 RVA: 0x0005C6EC File Offset: 0x0005A8EC
    private static IntPtr GetRealSectionSize(ref DLLFromMemory.IMAGE_SECTION_HEADER Section, ref DLLFromMemory.IMAGE_NT_HEADERS NTHeaders)
    {
        uint num = Section.SizeOfRawData;
        bool flag = num == 0U;
        if (flag)
        {
            bool flag2 = (Section.Characteristics & 64U) > 0U;
            if (flag2)
            {
                num = NTHeaders.OptionalHeader.SizeOfInitializedData;
            }
            else
            {
                bool flag3 = (Section.Characteristics & 128U) > 0U;
                if (flag3)
                {
                    num = NTHeaders.OptionalHeader.SizeOfUninitializedData;
                }
            }
        }
        return (IntPtr.Size == 8) ? ((IntPtr)((long)((ulong)num))) : ((IntPtr)((int)num));
    }

    // Token: 0x060000B6 RID: 182 RVA: 0x0005C769 File Offset: 0x0005A969
    public void Close()
    {
        ((IDisposable)this).Dispose();
    }

    // Token: 0x060000B7 RID: 183 RVA: 0x0005C773 File Offset: 0x0005A973
    void IDisposable.Dispose()
    {
        this.Dispose();
        GC.SuppressFinalize(this);
    }

    // Token: 0x060000B8 RID: 184 RVA: 0x0005C784 File Offset: 0x0005A984
    public void Dispose()
    {
        bool initialized = this._initialized;
        if (initialized)
        {
            bool flag = this._dllEntry != null;
            if (flag)
            {
                this._dllEntry(this.pCode, DLLFromMemory.DllReason.DLL_PROCESS_DETACH, IntPtr.Zero);
            }
            this._initialized = false;
        }
        bool flag2 = this.ImportModules != null;
        if (flag2)
        {
            foreach (IntPtr intPtr in this.ImportModules)
            {
                bool flag3 = !DLLFromMemory.PtrIsInvalidHandle(intPtr);
                if (flag3)
                {
                    DLLFromMemory.Win.FreeLibrary(intPtr);
                }
            }
            this.ImportModules = null;
        }
        bool flag4 = this.pCode != IntPtr.Zero;
        if (flag4)
        {
            DLLFromMemory.Win.VirtualFree(this.pCode, IntPtr.Zero, DLLFromMemory.AllocationType.RELEASE);
            this.pCode = IntPtr.Zero;
            this.pNTHeaders = IntPtr.Zero;
        }
        this.Disposed = true;
    }

    // Token: 0x060000B9 RID: 185 RVA: 0x0005C864 File Offset: 0x0005AA64
    private static T PtrRead<T>(IntPtr ptr)
    {
        return (T)((object)Marshal.PtrToStructure(ptr, typeof(T)));
    }

    // Token: 0x060000BA RID: 186 RVA: 0x0005C88B File Offset: 0x0005AA8B
    private static void PtrWrite<T>(IntPtr ptr, T val)
    {
        Marshal.StructureToPtr<T>(val, ptr, false);
    }

    // Token: 0x060000BB RID: 187 RVA: 0x0005C898 File Offset: 0x0005AA98
    private static IntPtr PtrAdd(IntPtr p, int v)
    {
        return (IntPtr)(p.ToInt64() + (long)v);
    }

    // Token: 0x060000BC RID: 188 RVA: 0x0005C8BC File Offset: 0x0005AABC
    private static IntPtr PtrAdd(IntPtr p, uint v)
    {
        return (IntPtr.Size == 8) ? ((IntPtr)(p.ToInt64() + (long)((ulong)v))) : ((IntPtr)(p.ToInt32() + (int)v));
    }

    // Token: 0x060000BD RID: 189 RVA: 0x0005C8F8 File Offset: 0x0005AAF8
    private static IntPtr PtrAdd(IntPtr p, IntPtr v)
    {
        return (IntPtr.Size == 8) ? ((IntPtr)(p.ToInt64() + v.ToInt64())) : ((IntPtr)(p.ToInt32() + v.ToInt32()));
    }

    // Token: 0x060000BE RID: 190 RVA: 0x0005C93C File Offset: 0x0005AB3C
    private static IntPtr PtrAdd(IntPtr p, UIntPtr v)
    {
        return (IntPtr.Size == 8) ? ((IntPtr)(p.ToInt64() + (long)v.ToUInt64())) : ((IntPtr)(p.ToInt32() + (int)v.ToUInt32()));
    }

    // Token: 0x060000BF RID: 191 RVA: 0x0005C980 File Offset: 0x0005AB80
    private static IntPtr PtrSub(IntPtr p, IntPtr v)
    {
        return (IntPtr.Size == 8) ? ((IntPtr)(p.ToInt64() - v.ToInt64())) : ((IntPtr)(p.ToInt32() - v.ToInt32()));
    }

    // Token: 0x060000C0 RID: 192 RVA: 0x0005C9C4 File Offset: 0x0005ABC4
    private static IntPtr PtrBitOr(IntPtr p, UIntPtr v)
    {
        return (IntPtr.Size == 8) ? ((IntPtr)(p.ToInt64() | (long)v.ToUInt64())) : ((IntPtr)(p.ToInt32() | (int)v.ToUInt32()));
    }

    // Token: 0x060000C1 RID: 193 RVA: 0x0005CA08 File Offset: 0x0005AC08
    private static IntPtr PtrAlignDown(IntPtr p, UIntPtr align)
    {
        return (IntPtr)(p.ToInt64() & (long)(~(long)(align.ToUInt64() - 1UL)));
    }

    // Token: 0x060000C2 RID: 194 RVA: 0x0005CA34 File Offset: 0x0005AC34
    private static bool PtrIsInvalidHandle(IntPtr h)
    {
        return h == IntPtr.Zero || h == ((IntPtr.Size == 8) ? ((IntPtr)(-1L)) : ((IntPtr)(-1)));
    }

    // Token: 0x060000C3 RID: 195 RVA: 0x0005CA74 File Offset: 0x0005AC74
    private static bool PtrSpanBoundary(IntPtr p, uint Size, int BoundaryBits)
    {
        return (ulong)p.ToInt64() >> BoundaryBits < (ulong)(p.ToInt64() + (long)((ulong)Size)) >> BoundaryBits;
    }

    // Token: 0x060000C4 RID: 196 RVA: 0x0005CAA4 File Offset: 0x0005ACA4
    private static T BytesReadStructAt<T>(byte[] buf, int offset)
    {
        int num = Marshal.SizeOf(typeof(T));
        IntPtr intPtr = Marshal.AllocHGlobal(num);
        Marshal.Copy(buf, offset, intPtr, num);
        T t = (T)((object)Marshal.PtrToStructure(intPtr, typeof(T)));
        Marshal.FreeHGlobal(intPtr);
        return t;
    }

    // Token: 0x040000AC RID: 172
    public IntPtr pCode = IntPtr.Zero;

    // Token: 0x040000AD RID: 173
    private IntPtr pNTHeaders = IntPtr.Zero;

    // Token: 0x040000AE RID: 174
    private IntPtr[] ImportModules;

    // Token: 0x040000AF RID: 175
    private bool _initialized = false;

    // Token: 0x040000B0 RID: 176
    private DLLFromMemory.DllEntryDelegate _dllEntry = null;

    // Token: 0x040000B1 RID: 177
    private DLLFromMemory.ExeEntryDelegate _exeEntry = null;

    // Token: 0x040000B2 RID: 178
    private bool _isRelocated = false;

    // Token: 0x040000B3 RID: 179
    private static readonly DLLFromMemory.PageProtection[,,] ProtectionFlags = new DLLFromMemory.PageProtection[,,]
    {
            {
                {
                    DLLFromMemory.PageProtection.NOACCESS,
                    DLLFromMemory.PageProtection.WRITECOPY
                },
                {
                    DLLFromMemory.PageProtection.READONLY,
                    DLLFromMemory.PageProtection.READWRITE
                }
            },
            {
                {
                    DLLFromMemory.PageProtection.EXECUTE,
                    DLLFromMemory.PageProtection.EXECUTE_WRITECOPY
                },
                {
                    DLLFromMemory.PageProtection.EXECUTE_READ,
                    DLLFromMemory.PageProtection.EXECUTE_READWRITE
                }
            }
    };

    // Token: 0x02000025 RID: 37
    public class DllException : Exception
    {
        // Token: 0x060000C6 RID: 198 RVA: 0x0005CB0F File Offset: 0x0005AD0F
        public DllException()
        {
        }

        // Token: 0x060000C7 RID: 199 RVA: 0x0005CB19 File Offset: 0x0005AD19
        public DllException(string message)
            : base(message)
        {
        }

        // Token: 0x060000C8 RID: 200 RVA: 0x0005CB24 File Offset: 0x0005AD24
        public DllException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }

    // Token: 0x02000026 RID: 38
    // (Invoke) Token: 0x060000CA RID: 202
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate bool DllEntryDelegate(IntPtr hinstDLL, DLLFromMemory.DllReason fdwReason, IntPtr lpReserved);

    // Token: 0x02000027 RID: 39
    // (Invoke) Token: 0x060000CE RID: 206
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate int ExeEntryDelegate();

    // Token: 0x02000028 RID: 40
    // (Invoke) Token: 0x060000D2 RID: 210
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void ImageTlsDelegate(IntPtr dllHandle, DLLFromMemory.DllReason reason, IntPtr reserved);

    // Token: 0x02000029 RID: 41
    private struct SectionFinalizeData
    {
        // Token: 0x040000B4 RID: 180
        internal IntPtr Address;

        // Token: 0x040000B5 RID: 181
        internal IntPtr AlignedAddress;

        // Token: 0x040000B6 RID: 182
        internal IntPtr Size;

        // Token: 0x040000B7 RID: 183
        internal uint Characteristics;

        // Token: 0x040000B8 RID: 184
        internal bool Last;
    }

    // Token: 0x0200002A RID: 42
    private class Of
    {
        // Token: 0x040000B9 RID: 185
        internal const int IMAGE_NT_HEADERS_OptionalHeader = 24;

        // Token: 0x040000BA RID: 186
        internal const int IMAGE_SECTION_HEADER_PhysicalAddress = 8;

        // Token: 0x040000BB RID: 187
        internal const int IMAGE_IMPORT_BY_NAME_Name = 2;
    }

    // Token: 0x0200002B RID: 43
    private class Of32
    {
        // Token: 0x040000BC RID: 188
        internal const int IMAGE_OPTIONAL_HEADER_ImageBase = 28;

        // Token: 0x040000BD RID: 189
        internal const int IMAGE_OPTIONAL_HEADER_ExportTable = 96;
    }

    // Token: 0x0200002C RID: 44
    private class Of64
    {
        // Token: 0x040000BE RID: 190
        internal const int IMAGE_OPTIONAL_HEADER_ImageBase = 24;

        // Token: 0x040000BF RID: 191
        internal const int IMAGE_OPTIONAL_HEADER_ExportTable = 112;
    }

    // Token: 0x0200002D RID: 45
    private class Sz
    {
        // Token: 0x040000C0 RID: 192
        internal const int IMAGE_SECTION_HEADER = 40;

        // Token: 0x040000C1 RID: 193
        internal const int IMAGE_BASE_RELOCATION = 8;

        // Token: 0x040000C2 RID: 194
        internal const int IMAGE_IMPORT_DESCRIPTOR = 20;
    }

    // Token: 0x0200002E RID: 46
    private struct IMAGE_DOS_HEADER
    {
        // Token: 0x040000C3 RID: 195
        public ushort e_magic;

        // Token: 0x040000C4 RID: 196
        public ushort e_cblp;

        // Token: 0x040000C5 RID: 197
        public ushort e_cp;

        // Token: 0x040000C6 RID: 198
        public ushort e_crlc;

        // Token: 0x040000C7 RID: 199
        public ushort e_cparhdr;

        // Token: 0x040000C8 RID: 200
        public ushort e_minalloc;

        // Token: 0x040000C9 RID: 201
        public ushort e_maxalloc;

        // Token: 0x040000CA RID: 202
        public ushort e_ss;

        // Token: 0x040000CB RID: 203
        public ushort e_sp;

        // Token: 0x040000CC RID: 204
        public ushort e_csum;

        // Token: 0x040000CD RID: 205
        public ushort e_ip;

        // Token: 0x040000CE RID: 206
        public ushort e_cs;

        // Token: 0x040000CF RID: 207
        public ushort e_lfarlc;

        // Token: 0x040000D0 RID: 208
        public ushort e_ovno;

        // Token: 0x040000D1 RID: 209
        public ushort e_res1a;

        // Token: 0x040000D2 RID: 210
        public ushort e_res1b;

        // Token: 0x040000D3 RID: 211
        public ushort e_res1c;

        // Token: 0x040000D4 RID: 212
        public ushort e_res1d;

        // Token: 0x040000D5 RID: 213
        public ushort e_oemid;

        // Token: 0x040000D6 RID: 214
        public ushort e_oeminfo;

        // Token: 0x040000D7 RID: 215
        public ushort e_res2a;

        // Token: 0x040000D8 RID: 216
        public ushort e_res2b;

        // Token: 0x040000D9 RID: 217
        public ushort e_res2c;

        // Token: 0x040000DA RID: 218
        public ushort e_res2d;

        // Token: 0x040000DB RID: 219
        public ushort e_res2e;

        // Token: 0x040000DC RID: 220
        public ushort e_res2f;

        // Token: 0x040000DD RID: 221
        public ushort e_res2g;

        // Token: 0x040000DE RID: 222
        public ushort e_res2h;

        // Token: 0x040000DF RID: 223
        public ushort e_res2i;

        // Token: 0x040000E0 RID: 224
        public ushort e_res2j;

        // Token: 0x040000E1 RID: 225
        public int e_lfanew;
    }

    // Token: 0x0200002F RID: 47
    private struct IMAGE_NT_HEADERS
    {
        // Token: 0x040000E2 RID: 226
        public uint Signature;

        // Token: 0x040000E3 RID: 227
        public DLLFromMemory.IMAGE_FILE_HEADER FileHeader;

        // Token: 0x040000E4 RID: 228
        public DLLFromMemory.IMAGE_OPTIONAL_HEADER OptionalHeader;
    }

    // Token: 0x02000030 RID: 48
    private struct IMAGE_FILE_HEADER
    {
        // Token: 0x040000E5 RID: 229
        public ushort Machine;

        // Token: 0x040000E6 RID: 230
        public ushort NumberOfSections;

        // Token: 0x040000E7 RID: 231
        public uint TimeDateStamp;

        // Token: 0x040000E8 RID: 232
        public uint PointerToSymbolTable;

        // Token: 0x040000E9 RID: 233
        public uint NumberOfSymbols;

        // Token: 0x040000EA RID: 234
        public ushort SizeOfOptionalHeader;

        // Token: 0x040000EB RID: 235
        public ushort Characteristics;
    }

    // Token: 0x02000031 RID: 49
    private struct IMAGE_OPTIONAL_HEADER
    {
        // Token: 0x040000EC RID: 236
        public DLLFromMemory.MagicType Magic;

        // Token: 0x040000ED RID: 237
        public byte MajorLinkerVersion;

        // Token: 0x040000EE RID: 238
        public byte MinorLinkerVersion;

        // Token: 0x040000EF RID: 239
        public uint SizeOfCode;

        // Token: 0x040000F0 RID: 240
        public uint SizeOfInitializedData;

        // Token: 0x040000F1 RID: 241
        public uint SizeOfUninitializedData;

        // Token: 0x040000F2 RID: 242
        public uint AddressOfEntryPoint;

        // Token: 0x040000F3 RID: 243
        public uint BaseOfCode;

        // Token: 0x040000F4 RID: 244
        public ulong ImageBaseLong;

        // Token: 0x040000F5 RID: 245
        public uint SectionAlignment;

        // Token: 0x040000F6 RID: 246
        public uint FileAlignment;

        // Token: 0x040000F7 RID: 247
        public ushort MajorOperatingSystemVersion;

        // Token: 0x040000F8 RID: 248
        public ushort MinorOperatingSystemVersion;

        // Token: 0x040000F9 RID: 249
        public ushort MajorImageVersion;

        // Token: 0x040000FA RID: 250
        public ushort MinorImageVersion;

        // Token: 0x040000FB RID: 251
        public ushort MajorSubsystemVersion;

        // Token: 0x040000FC RID: 252
        public ushort MinorSubsystemVersion;

        // Token: 0x040000FD RID: 253
        public uint Win32VersionValue;

        // Token: 0x040000FE RID: 254
        public uint SizeOfImage;

        // Token: 0x040000FF RID: 255
        public uint SizeOfHeaders;

        // Token: 0x04000100 RID: 256
        public uint CheckSum;

        // Token: 0x04000101 RID: 257
        public DLLFromMemory.SubSystemType Subsystem;

        // Token: 0x04000102 RID: 258
        public DLLFromMemory.DllCharacteristicsType DllCharacteristics;

        // Token: 0x04000103 RID: 259
        public IntPtr SizeOfStackReserve;

        // Token: 0x04000104 RID: 260
        public IntPtr SizeOfStackCommit;

        // Token: 0x04000105 RID: 261
        public IntPtr SizeOfHeapReserve;

        // Token: 0x04000106 RID: 262
        public IntPtr SizeOfHeapCommit;

        // Token: 0x04000107 RID: 263
        public uint LoaderFlags;

        // Token: 0x04000108 RID: 264
        public uint NumberOfRvaAndSizes;

        // Token: 0x04000109 RID: 265
        public DLLFromMemory.IMAGE_DATA_DIRECTORY ExportTable;

        // Token: 0x0400010A RID: 266
        public DLLFromMemory.IMAGE_DATA_DIRECTORY ImportTable;

        // Token: 0x0400010B RID: 267
        public DLLFromMemory.IMAGE_DATA_DIRECTORY ResourceTable;

        // Token: 0x0400010C RID: 268
        public DLLFromMemory.IMAGE_DATA_DIRECTORY ExceptionTable;

        // Token: 0x0400010D RID: 269
        public DLLFromMemory.IMAGE_DATA_DIRECTORY CertificateTable;

        // Token: 0x0400010E RID: 270
        public DLLFromMemory.IMAGE_DATA_DIRECTORY BaseRelocationTable;

        // Token: 0x0400010F RID: 271
        public DLLFromMemory.IMAGE_DATA_DIRECTORY Debug;

        // Token: 0x04000110 RID: 272
        public DLLFromMemory.IMAGE_DATA_DIRECTORY Architecture;

        // Token: 0x04000111 RID: 273
        public DLLFromMemory.IMAGE_DATA_DIRECTORY GlobalPtr;

        // Token: 0x04000112 RID: 274
        public DLLFromMemory.IMAGE_DATA_DIRECTORY TLSTable;

        // Token: 0x04000113 RID: 275
        public DLLFromMemory.IMAGE_DATA_DIRECTORY LoadConfigTable;

        // Token: 0x04000114 RID: 276
        public DLLFromMemory.IMAGE_DATA_DIRECTORY BoundImport;

        // Token: 0x04000115 RID: 277
        public DLLFromMemory.IMAGE_DATA_DIRECTORY IAT;

        // Token: 0x04000116 RID: 278
        public DLLFromMemory.IMAGE_DATA_DIRECTORY DelayImportDescriptor;

        // Token: 0x04000117 RID: 279
        public DLLFromMemory.IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

        // Token: 0x04000118 RID: 280
        public DLLFromMemory.IMAGE_DATA_DIRECTORY Reserved;
    }

    // Token: 0x02000032 RID: 50
    private struct IMAGE_DATA_DIRECTORY
    {
        // Token: 0x04000119 RID: 281
        public uint VirtualAddress;

        // Token: 0x0400011A RID: 282
        public uint Size;
    }

    // Token: 0x02000033 RID: 51
    private struct IMAGE_SECTION_HEADER
    {
        // Token: 0x0400011B RID: 283
        public ulong Name;

        // Token: 0x0400011C RID: 284
        public uint PhysicalAddress;

        // Token: 0x0400011D RID: 285
        public uint VirtualAddress;

        // Token: 0x0400011E RID: 286
        public uint SizeOfRawData;

        // Token: 0x0400011F RID: 287
        public uint PointerToRawData;

        // Token: 0x04000120 RID: 288
        public uint PointerToRelocations;

        // Token: 0x04000121 RID: 289
        public uint PointerToLinenumbers;

        // Token: 0x04000122 RID: 290
        public ushort NumberOfRelocations;

        // Token: 0x04000123 RID: 291
        public ushort NumberOfLinenumbers;

        // Token: 0x04000124 RID: 292
        public uint Characteristics;
    }

    // Token: 0x02000034 RID: 52
    private struct IMAGE_BASE_RELOCATION
    {
        // Token: 0x04000125 RID: 293
        public uint VirtualAdress;

        // Token: 0x04000126 RID: 294
        public uint SizeOfBlock;
    }

    // Token: 0x02000035 RID: 53
    private struct IMAGE_IMPORT_DESCRIPTOR
    {
        // Token: 0x04000127 RID: 295
        public uint OriginalFirstThunk;

        // Token: 0x04000128 RID: 296
        public uint TimeDateStamp;

        // Token: 0x04000129 RID: 297
        public uint ForwarderChain;

        // Token: 0x0400012A RID: 298
        public uint Name;

        // Token: 0x0400012B RID: 299
        public uint FirstThunk;
    }

    // Token: 0x02000036 RID: 54
    private struct IMAGE_EXPORT_DIRECTORY
    {
        // Token: 0x0400012C RID: 300
        public uint Characteristics;

        // Token: 0x0400012D RID: 301
        public uint TimeDateStamp;

        // Token: 0x0400012E RID: 302
        public ushort MajorVersion;

        // Token: 0x0400012F RID: 303
        public ushort MinorVersion;

        // Token: 0x04000130 RID: 304
        public uint Name;

        // Token: 0x04000131 RID: 305
        public uint Base;

        // Token: 0x04000132 RID: 306
        public uint NumberOfFunctions;

        // Token: 0x04000133 RID: 307
        public uint NumberOfNames;

        // Token: 0x04000134 RID: 308
        public uint AddressOfFunctions;

        // Token: 0x04000135 RID: 309
        public uint AddressOfNames;

        // Token: 0x04000136 RID: 310
        public uint AddressOfNameOrdinals;
    }

    // Token: 0x02000037 RID: 55
    private struct SYSTEM_INFO
    {
        // Token: 0x04000137 RID: 311
        public ushort wProcessorArchitecture;

        // Token: 0x04000138 RID: 312
        public ushort wReserved;

        // Token: 0x04000139 RID: 313
        public uint dwPageSize;

        // Token: 0x0400013A RID: 314
        public IntPtr lpMinimumApplicationAddress;

        // Token: 0x0400013B RID: 315
        public IntPtr lpMaximumApplicationAddress;

        // Token: 0x0400013C RID: 316
        public IntPtr dwActiveProcessorMask;

        // Token: 0x0400013D RID: 317
        public uint dwNumberOfProcessors;

        // Token: 0x0400013E RID: 318
        public uint dwProcessorType;

        // Token: 0x0400013F RID: 319
        public uint dwAllocationGranularity;

        // Token: 0x04000140 RID: 320
        public ushort wProcessorLevel;

        // Token: 0x04000141 RID: 321
        public ushort wProcessorRevision;
    }

    // Token: 0x02000038 RID: 56
    private struct IMAGE_TLS_DIRECTORY
    {
        // Token: 0x04000142 RID: 322
        public IntPtr StartAddressOfRawData;

        // Token: 0x04000143 RID: 323
        public IntPtr EndAddressOfRawData;

        // Token: 0x04000144 RID: 324
        public IntPtr AddressOfIndex;

        // Token: 0x04000145 RID: 325
        public IntPtr AddressOfCallBacks;

        // Token: 0x04000146 RID: 326
        public IntPtr SizeOfZeroFill;

        // Token: 0x04000147 RID: 327
        public uint Characteristics;
    }

    // Token: 0x02000039 RID: 57
    private enum MagicType : ushort
    {
        // Token: 0x04000149 RID: 329
        IMAGE_NT_OPTIONAL_HDR32_MAGIC = 267,
        // Token: 0x0400014A RID: 330
        IMAGE_NT_OPTIONAL_HDR64_MAGIC = 523
    }

    // Token: 0x0200003A RID: 58
    private enum SubSystemType : ushort
    {
        // Token: 0x0400014C RID: 332
        IMAGE_SUBSYSTEM_UNKNOWN,
        // Token: 0x0400014D RID: 333
        IMAGE_SUBSYSTEM_NATIVE,
        // Token: 0x0400014E RID: 334
        IMAGE_SUBSYSTEM_WINDOWS_GUI,
        // Token: 0x0400014F RID: 335
        IMAGE_SUBSYSTEM_WINDOWS_CUI,
        // Token: 0x04000150 RID: 336
        IMAGE_SUBSYSTEM_POSIX_CUI = 7,
        // Token: 0x04000151 RID: 337
        IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
        // Token: 0x04000152 RID: 338
        IMAGE_SUBSYSTEM_EFI_APPLICATION,
        // Token: 0x04000153 RID: 339
        IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER,
        // Token: 0x04000154 RID: 340
        IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER,
        // Token: 0x04000155 RID: 341
        IMAGE_SUBSYSTEM_EFI_ROM,
        // Token: 0x04000156 RID: 342
        IMAGE_SUBSYSTEM_XBOX
    }

    // Token: 0x0200003B RID: 59
    private enum DllCharacteristicsType : ushort
    {
        // Token: 0x04000158 RID: 344
        RES_0 = 1,
        // Token: 0x04000159 RID: 345
        RES_1,
        // Token: 0x0400015A RID: 346
        RES_2 = 4,
        // Token: 0x0400015B RID: 347
        RES_3 = 8,
        // Token: 0x0400015C RID: 348
        IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 64,
        // Token: 0x0400015D RID: 349
        IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 128,
        // Token: 0x0400015E RID: 350
        IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 256,
        // Token: 0x0400015F RID: 351
        IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 512,
        // Token: 0x04000160 RID: 352
        IMAGE_DLLCHARACTERISTICS_NO_SEH = 1024,
        // Token: 0x04000161 RID: 353
        IMAGE_DLLCHARACTERISTICS_NO_BIND = 2048,
        // Token: 0x04000162 RID: 354
        RES_4 = 4096,
        // Token: 0x04000163 RID: 355
        IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 8192,
        // Token: 0x04000164 RID: 356
        IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 32768
    }

    // Token: 0x0200003C RID: 60
    private enum BasedRelocationType
    {
        // Token: 0x04000166 RID: 358
        IMAGE_REL_BASED_ABSOLUTE,
        // Token: 0x04000167 RID: 359
        IMAGE_REL_BASED_HIGH,
        // Token: 0x04000168 RID: 360
        IMAGE_REL_BASED_LOW,
        // Token: 0x04000169 RID: 361
        IMAGE_REL_BASED_HIGHLOW,
        // Token: 0x0400016A RID: 362
        IMAGE_REL_BASED_HIGHADJ,
        // Token: 0x0400016B RID: 363
        IMAGE_REL_BASED_MIPS_JMPADDR,
        // Token: 0x0400016C RID: 364
        IMAGE_REL_BASED_MIPS_JMPADDR16 = 9,
        // Token: 0x0400016D RID: 365
        IMAGE_REL_BASED_IA64_IMM64 = 9,
        // Token: 0x0400016E RID: 366
        IMAGE_REL_BASED_DIR64
    }

    // Token: 0x0200003D RID: 61
    private enum AllocationType : uint
    {
        // Token: 0x04000170 RID: 368
        COMMIT = 4096U,
        // Token: 0x04000171 RID: 369
        RESERVE = 8192U,
        // Token: 0x04000172 RID: 370
        RESET = 524288U,
        // Token: 0x04000173 RID: 371
        LARGE_PAGES = 536870912U,
        // Token: 0x04000174 RID: 372
        PHYSICAL = 4194304U,
        // Token: 0x04000175 RID: 373
        TOP_DOWN = 1048576U,
        // Token: 0x04000176 RID: 374
        WRITE_WATCH = 2097152U,
        // Token: 0x04000177 RID: 375
        DECOMMIT = 16384U,
        // Token: 0x04000178 RID: 376
        RELEASE = 32768U
    }

    // Token: 0x0200003E RID: 62
    private enum MemoryProtection : uint
    {
        // Token: 0x0400017A RID: 378
        EXECUTE = 16U,
        // Token: 0x0400017B RID: 379
        EXECUTE_READ = 32U,
        // Token: 0x0400017C RID: 380
        EXECUTE_READWRITE = 64U,
        // Token: 0x0400017D RID: 381
        EXECUTE_WRITECOPY = 128U,
        // Token: 0x0400017E RID: 382
        NOACCESS = 1U,
        // Token: 0x0400017F RID: 383
        READONLY,
        // Token: 0x04000180 RID: 384
        READWRITE = 4U,
        // Token: 0x04000181 RID: 385
        WRITECOPY = 8U,
        // Token: 0x04000182 RID: 386
        GUARD_Modifierflag = 256U,
        // Token: 0x04000183 RID: 387
        NOCACHE_Modifierflag = 512U,
        // Token: 0x04000184 RID: 388
        WRITECOMBINE_Modifierflag = 1024U
    }

    // Token: 0x0200003F RID: 63
    private enum PageProtection
    {
        // Token: 0x04000186 RID: 390
        NOACCESS = 1,
        // Token: 0x04000187 RID: 391
        READONLY,
        // Token: 0x04000188 RID: 392
        READWRITE = 4,
        // Token: 0x04000189 RID: 393
        WRITECOPY = 8,
        // Token: 0x0400018A RID: 394
        EXECUTE = 16,
        // Token: 0x0400018B RID: 395
        EXECUTE_READ = 32,
        // Token: 0x0400018C RID: 396
        EXECUTE_READWRITE = 64,
        // Token: 0x0400018D RID: 397
        EXECUTE_WRITECOPY = 128,
        // Token: 0x0400018E RID: 398
        GUARD = 256,
        // Token: 0x0400018F RID: 399
        NOCACHE = 512,
        // Token: 0x04000190 RID: 400
        WRITECOMBINE = 1024
    }

    // Token: 0x02000040 RID: 64
    private enum ImageSectionFlags : uint
    {
        // Token: 0x04000192 RID: 402
        IMAGE_SCN_LNK_NRELOC_OVFL = 16777216U,
        // Token: 0x04000193 RID: 403
        IMAGE_SCN_MEM_DISCARDABLE = 33554432U,
        // Token: 0x04000194 RID: 404
        IMAGE_SCN_MEM_NOT_CACHED = 67108864U,
        // Token: 0x04000195 RID: 405
        IMAGE_SCN_MEM_NOT_PAGED = 134217728U,
        // Token: 0x04000196 RID: 406
        IMAGE_SCN_MEM_SHARED = 268435456U,
        // Token: 0x04000197 RID: 407
        IMAGE_SCN_MEM_EXECUTE = 536870912U,
        // Token: 0x04000198 RID: 408
        IMAGE_SCN_MEM_READ = 1073741824U,
        // Token: 0x04000199 RID: 409
        IMAGE_SCN_MEM_WRITE = 2147483648U
    }

    // Token: 0x02000041 RID: 65
    private enum DllReason : uint
    {
        // Token: 0x0400019B RID: 411
        DLL_PROCESS_ATTACH = 1U,
        // Token: 0x0400019C RID: 412
        DLL_THREAD_ATTACH,
        // Token: 0x0400019D RID: 413
        DLL_THREAD_DETACH,
        // Token: 0x0400019E RID: 414
        DLL_PROCESS_DETACH = 0U
    }

    // Token: 0x02000042 RID: 66
    private class Win
    {
        // Token: 0x060000D9 RID: 217
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, DLLFromMemory.AllocationType flAllocationType, DLLFromMemory.MemoryProtection flProtect);

        // Token: 0x060000DA RID: 218
        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "memset")]
        public static extern IntPtr MemSet(IntPtr dest, int c, UIntPtr count);

        // Token: 0x060000DB RID: 219
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr LoadLibrary(IntPtr lpFileName);

        // Token: 0x060000DC RID: 220
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, IntPtr procName);

        // Token: 0x060000DD RID: 221
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualFree(IntPtr lpAddress, IntPtr dwSize, DLLFromMemory.AllocationType dwFreeType);

        // Token: 0x060000DE RID: 222
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtect(IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        // Token: 0x060000DF RID: 223
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FreeLibrary(IntPtr hModule);

        // Token: 0x060000E0 RID: 224
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void GetNativeSystemInfo(out DLLFromMemory.SYSTEM_INFO lpSystemInfo);

        // Token: 0x060000E1 RID: 225 RVA: 0x0005CB30 File Offset: 0x0005AD30
        public static IntPtr IMAGE_FIRST_SECTION(IntPtr pNTHeader, ushort ntheader_FileHeader_SizeOfOptionalHeader)
        {
            return DLLFromMemory.PtrAdd(pNTHeader, (int)(24 + ntheader_FileHeader_SizeOfOptionalHeader));
        }

        // Token: 0x060000E2 RID: 226 RVA: 0x0005CB4C File Offset: 0x0005AD4C
        public static int IMAGE_FIRST_SECTION(int lfanew, ushort ntheader_FileHeader_SizeOfOptionalHeader)
        {
            return lfanew + 24 + (int)ntheader_FileHeader_SizeOfOptionalHeader;
        }

        // Token: 0x060000E3 RID: 227 RVA: 0x0005CB64 File Offset: 0x0005AD64
        public static IntPtr IMAGE_ORDINAL(IntPtr ordinal)
        {
            return (IntPtr)((int)(ordinal.ToInt64() & 65535L));
        }

        // Token: 0x060000E4 RID: 228 RVA: 0x0005CB8C File Offset: 0x0005AD8C
        public static bool IMAGE_SNAP_BY_ORDINAL(IntPtr ordinal)
        {
            return (IntPtr.Size == 8) ? (ordinal.ToInt64() < 0L) : (ordinal.ToInt32() < 0);
        }

        // Token: 0x0400019F RID: 415
        public const ushort IMAGE_DOS_SIGNATURE = 23117;

        // Token: 0x040001A0 RID: 416
        public const uint IMAGE_NT_SIGNATURE = 17744U;

        // Token: 0x040001A1 RID: 417
        public const uint IMAGE_FILE_MACHINE_I386 = 332U;

        // Token: 0x040001A2 RID: 418
        public const uint IMAGE_FILE_MACHINE_AMD64 = 34404U;

        // Token: 0x040001A3 RID: 419
        public const uint PAGE_NOCACHE = 512U;

        // Token: 0x040001A4 RID: 420
        public const uint IMAGE_SCN_CNT_INITIALIZED_DATA = 64U;

        // Token: 0x040001A5 RID: 421
        public const uint IMAGE_SCN_CNT_UNINITIALIZED_DATA = 128U;

        // Token: 0x040001A6 RID: 422
        public const uint IMAGE_SCN_MEM_DISCARDABLE = 33554432U;

        // Token: 0x040001A7 RID: 423
        public const uint IMAGE_SCN_MEM_NOT_CACHED = 67108864U;

        // Token: 0x040001A8 RID: 424
        public const uint IMAGE_FILE_DLL = 8192U;
    }
}
