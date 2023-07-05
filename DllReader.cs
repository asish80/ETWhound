﻿using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Xml.Linq;
using static ETWHound.NamedPipeSniffer;

namespace ETWHound
{
        class DllReader
        {
            // Can't use sizeof for IMAGE_SECTION_HEADER because of unmanaged type
            public const int SizeOfImageSectionHeader = 40;

            [System.Flags]
            enum LoadLibraryFlags : uint
            {
                None = 0,
                DONT_RESOLVE_DLL_REFERENCES = 0x00000001,
                LOAD_IGNORE_CODE_AUTHZ_LEVEL = 0x00000010,
                LOAD_LIBRARY_AS_DATAFILE = 0x00000002,
                LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = 0x00000040,
                LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020,
                LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200,
                LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000,
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x00000100,
                LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800,
                LOAD_LIBRARY_SEARCH_USER_DIRS = 0x00000400,
                LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008
            }

            [StructLayout(LayoutKind.Sequential, Pack = 4)]
            public unsafe struct IMAGE_DOS_HEADER
            {
                public UInt16 e_magic;              // Magic number
                public UInt16 e_cblp;               // Bytes on last page of file
                public UInt16 e_cp;                 // Pages in file
                public UInt16 e_crlc;               // Relocations
                public UInt16 e_cparhdr;            // Size of header in paragraphs
                public UInt16 e_minalloc;           // Minimum extra paragraphs needed
                public UInt16 e_maxalloc;           // Maximum extra paragraphs needed
                public UInt16 e_ss;                 // Initial (relative) SS value
                public UInt16 e_sp;                 // Initial SP value
                public UInt16 e_csum;               // Checksum
                public UInt16 e_ip;                 // Initial IP value
                public UInt16 e_cs;                 // Initial (relative) CS value
                public UInt16 e_lfarlc;             // File address of relocation table
                public UInt16 e_ovno;               // Overlay number
                public UInt16 e_res_0;              // Reserved words
                public UInt16 e_res_1;              // Reserved words
                public UInt16 e_res_2;              // Reserved words
                public UInt16 e_res_3;              // Reserved words
                public UInt16 e_oemid;              // OEM identifier (for e_oeminfo)
                public UInt16 e_oeminfo;            // OEM information; e_oemid specific
                public UInt16 e_res2_0;             // Reserved words
                public UInt16 e_res2_1;             // Reserved words
                public UInt16 e_res2_2;             // Reserved words
                public UInt16 e_res2_3;             // Reserved words
                public UInt16 e_res2_4;             // Reserved words
                public UInt16 e_res2_5;             // Reserved words
                public UInt16 e_res2_6;             // Reserved words
                public UInt16 e_res2_7;             // Reserved words
                public UInt16 e_res2_8;             // Reserved words
                public UInt16 e_res2_9;             // Reserved words
                public Int32 e_lfanew;             // File address of new exe header
            }

            [StructLayout(LayoutKind.Sequential, Pack = 4)]
            public unsafe struct IMAGE_DATA_DIRECTORY
            {
                public UInt32 VirtualAddress;
                public UInt32 Size;
            }

            [StructLayout(LayoutKind.Sequential, Pack = 4)]
            public unsafe struct IMAGE_FILE_HEADER
            {
                public UInt16 Machine;
                public UInt16 NumberOfSections;
                public UInt32 TimeDateStamp;
                public UInt32 PointerToSymbolTable;
                public UInt32 NumberOfSymbols;
                public UInt16 SizeOfOptionalHeader;
                public UInt16 Characteristics;
            }

            [StructLayout(LayoutKind.Sequential)]
            public unsafe struct IMAGE_OPTIONAL_HEADER64
            {
                public UInt16 Magic;
                public byte MajorLinkerVersion;
                public byte MinorLinkerVersion;
                public uint SizeOfCode;
                public uint SizeOfInitializedData;
                public uint SizeOfUninitializedData;
                public uint AddressOfEntryPoint;
                public uint BaseOfCode;
                public ulong ImageBaseLong;
                public uint SectionAlignment;
                public uint FileAlignment;
                public ushort MajorOperatingSystemVersion;
                public ushort MinorOperatingSystemVersion;
                public ushort MajorImageVersion;
                public ushort MinorImageVersion;
                public ushort MajorSubsystemVersion;
                public ushort MinorSubsystemVersion;
                public uint Win32VersionValue;
                public uint SizeOfImage;
                public uint SizeOfHeaders;
                public uint CheckSum;
                public UInt16 Subsystem;
                public UInt16 DllCharacteristics;
                public ulong SizeOfStackReserve;
                public ulong SizeOfStackCommit;
                public ulong SizeOfHeapReserve;
                public ulong SizeOfHeapCommit;
                public uint LoaderFlags;
                public uint NumberOfRvaAndSizes;
                public IMAGE_DATA_DIRECTORY ExportTable;
                public IMAGE_DATA_DIRECTORY ImportTable;
                public IMAGE_DATA_DIRECTORY ResourceTable;
                public IMAGE_DATA_DIRECTORY ExceptionTable;
                public IMAGE_DATA_DIRECTORY CertificateTable;
                public IMAGE_DATA_DIRECTORY BaseRelocationTable;
                public IMAGE_DATA_DIRECTORY Debug;
                public IMAGE_DATA_DIRECTORY Architecture;
                public IMAGE_DATA_DIRECTORY GlobalPtr;
                public IMAGE_DATA_DIRECTORY TLSTable;
                public IMAGE_DATA_DIRECTORY LoadConfigTable;
                public IMAGE_DATA_DIRECTORY BoundImport;
                public IMAGE_DATA_DIRECTORY IAT;
                public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
                public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
                public IMAGE_DATA_DIRECTORY Reserved;
            }

            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct IMAGE_OPTIONAL_HEADER32
            {
                public UInt16 Magic;
                public Byte MajorLinkerVersion;
                public Byte MinorLinkerVersion;
                public UInt32 SizeOfCode;
                public UInt32 SizeOfInitializedData;
                public UInt32 SizeOfUninitializedData;
                public UInt32 AddressOfEntryPoint;
                public UInt32 BaseOfCode;
                public UInt32 BaseOfData;
                public UInt32 ImageBase;
                public UInt32 SectionAlignment;
                public UInt32 FileAlignment;
                public UInt16 MajorOperatingSystemVersion;
                public UInt16 MinorOperatingSystemVersion;
                public UInt16 MajorImageVersion;
                public UInt16 MinorImageVersion;
                public UInt16 MajorSubsystemVersion;
                public UInt16 MinorSubsystemVersion;
                public UInt32 Win32VersionValue;
                public UInt32 SizeOfImage;
                public UInt32 SizeOfHeaders;
                public UInt32 CheckSum;
                public UInt16 Subsystem;
                public UInt16 DllCharacteristics;
                public UInt32 SizeOfStackReserve;
                public UInt32 SizeOfStackCommit;
                public UInt32 SizeOfHeapReserve;
                public UInt32 SizeOfHeapCommit;
                public UInt32 LoaderFlags;
                public UInt32 NumberOfRvaAndSizes;

                public IMAGE_DATA_DIRECTORY ExportTable;
                public IMAGE_DATA_DIRECTORY ImportTable;
                public IMAGE_DATA_DIRECTORY ResourceTable;
                public IMAGE_DATA_DIRECTORY ExceptionTable;
                public IMAGE_DATA_DIRECTORY CertificateTable;
                public IMAGE_DATA_DIRECTORY BaseRelocationTable;
                public IMAGE_DATA_DIRECTORY Debug;
                public IMAGE_DATA_DIRECTORY Architecture;
                public IMAGE_DATA_DIRECTORY GlobalPtr;
                public IMAGE_DATA_DIRECTORY TLSTable;
                public IMAGE_DATA_DIRECTORY LoadConfigTable;
                public IMAGE_DATA_DIRECTORY BoundImport;
                public IMAGE_DATA_DIRECTORY IAT;
                public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
                public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
                public IMAGE_DATA_DIRECTORY Reserved;
            }

            [StructLayout(LayoutKind.Sequential)]
            public unsafe struct IMAGE_NT_HEADERS32
            {
                public UInt32 Signature;
                public IMAGE_FILE_HEADER FileHeader;
                public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
            }

            [StructLayout(LayoutKind.Sequential)]
            public unsafe struct IMAGE_NT_HEADERS64
            {
                public UInt32 Signature;
                public IMAGE_FILE_HEADER FileHeader;
                public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
            }

            [StructLayout(LayoutKind.Sequential)]
            public unsafe struct IMAGE_EXPORT_DIRECTORY
            {
                public UInt32 Characteristics;
                public UInt32 TimeDateStamp;
                public UInt16 MajorVersion;
                public UInt16 MinorVersion;
                public UInt32 Name;
                public UInt32 Base;
                public UInt32 NumberOfFunctions;
                public UInt32 NumberOfNames;
                public UInt32 AddressOfFunctions; // RVA from base of image
                public UInt32 AddressOfNames; // RVA from base of image
                public UInt32 AddressOfNameOrdinals; // RVA from base of image
            }

            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_SECTION_HEADER
            {
                [FieldOffset(0)]
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
                public char[] Name;
                [FieldOffset(8)]
                public UInt32 VirtualSize;
                [FieldOffset(12)]
                public UInt32 VirtualAddress;
                [FieldOffset(16)]
                public UInt32 SizeOfRawData;
                [FieldOffset(20)]
                public UInt32 PointerToRawData;
                [FieldOffset(24)]
                public UInt32 PointerToRelocations;
                [FieldOffset(28)]
                public UInt32 PointerToLinenumbers;
                [FieldOffset(32)]
                public UInt16 NumberOfRelocations;
                [FieldOffset(34)]
                public UInt16 NumberOfLinenumbers;
                [FieldOffset(36)]
                uint Characteristics;

                public string Section
                {
                    get { return new string(Name); }
                }
            }

            [DllImport("kernel32.dll", SetLastError = true)]
            static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hReservedNull, LoadLibraryFlags dwFlags);

            public static T CastBytesToType<T>(byte[] bytes)
            {
                GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
                T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
                handle.Free();

                return theStructure;
            }

            //static unsafe void Main(string[] args)
            //{
                //  Console.WriteLine("\nParse exports by first loading the DLL\n");
                //    LoadDLL(@"C:\Users\gvaradarajan\source\repos\Dll1\x64\Debug\Dll1.dll");
              //  Console.WriteLine("\nParse exports by parsing the DLL without loading it\n");
              //  ReadFromFile(@"C:\Users\gvaradarajan\source\repos\Dll1\x64\Debug\Dll1.dll");
            //}

            static unsafe void LoadDLL(string DLL)
            {
                // Load DLL, use LoadLibraryEx to prevent DLLMain from executing
                IntPtr handle = LoadLibraryEx(DLL, IntPtr.Zero, LoadLibraryFlags.DONT_RESOLVE_DLL_REFERENCES);

                // Get IMAGE_DOS_HEADER because we need e_lfanew for offset to IMAGE_NT_HEADER
                IMAGE_DOS_HEADER imageDosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(handle, typeof(IMAGE_DOS_HEADER));

                // Get IMAGE_NT_HEADER because we need it for address of export table
                IMAGE_NT_HEADERS64 imageNtHeader = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(IntPtr.Add(handle, imageDosHeader.e_lfanew), typeof(IMAGE_NT_HEADERS64));

                // Get IMAGE_EXPORT_DIRECTORY
                IMAGE_EXPORT_DIRECTORY exportTable = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(IntPtr.Add(handle, (int)imageNtHeader.OptionalHeader.ExportTable.VirtualAddress), typeof(IMAGE_EXPORT_DIRECTORY));

                // Loop through function names

                IntPtr NamesPointer = IntPtr.Add(handle, (int)exportTable.AddressOfNames);
                string[] function_names = new string[exportTable.NumberOfNames];

                for (int i = 0; i < exportTable.NumberOfNames; i++)
                {
                    int offset = Marshal.ReadInt32(NamesPointer);
                    function_names[i] = Marshal.PtrToStringAnsi(IntPtr.Add(handle, offset));
                    NamesPointer = IntPtr.Add(NamesPointer, 4);
                }

                // Loop through ordinals for functions with names

                IntPtr OrdinalPointer = IntPtr.Add(handle, (int)exportTable.AddressOfNameOrdinals);
                short[] ordinals = new short[exportTable.NumberOfNames];
                for (int i = 0; i < exportTable.NumberOfNames; i++)
                {
                    ordinals[i] = (short)(Marshal.ReadInt16(OrdinalPointer) + exportTable.Base);
                    OrdinalPointer = IntPtr.Add(OrdinalPointer, 2);
                }

                // Loop through functions to get RVA values

                IntPtr FunctionsPointer = IntPtr.Add(handle, (int)exportTable.AddressOfFunctions);
                int[] functionRVAs = new int[exportTable.NumberOfFunctions];
                for (int i = 0; i < exportTable.NumberOfFunctions; i++)
                {
                    functionRVAs[i] = Marshal.ReadInt32(FunctionsPointer);
                    FunctionsPointer = IntPtr.Add(FunctionsPointer, 4);
                }

                // Print output to mimic dumpbin export output

                Console.WriteLine("\tordinal\thint\tRVA\t\tname");

                for (int i = 0; i < exportTable.NumberOfNames; i++)
                {
                    int function_idx = (int)(ordinals[i] - exportTable.Base);
                    Console.WriteLine("\t" + ordinals[i] + "\t" + i.ToString("X") + "\t" + String.Format("{0:X8}", functionRVAs[function_idx]) + "\t" + function_names[i]);
                }

                // Everything without a function name must be a nameless export with an ordinal

                for (int i = 0; i < exportTable.NumberOfFunctions; i++)
                {
                    short ord = (short)(i + exportTable.Base);
                    if (!ordinals.Contains(ord) && functionRVAs[i] != 0)
                    {
                        Console.WriteLine("\t" + ord + "\t\t" + String.Format("{0:X8}", functionRVAs[i]) + "\t[NONAME]");
                    }
                }
            }

            static public unsafe void ReadFromFile(string DLL, Guid nnid)
            {
                // Read bytes of DLL
                byte[] sourceFileByteBuffer = System.IO.File.ReadAllBytes(DLL);

                // Get IMAGE_DOS_HEADER because we need e_lfanew for offset to IMAGE_NT_HEADER
                IMAGE_DOS_HEADER imageDosHeader = CastBytesToType<IMAGE_DOS_HEADER>(sourceFileByteBuffer.Skip(0).Take(sizeof(IMAGE_DOS_HEADER)).ToArray());

                // Get IMAGE_FILE_HEADER to check if the DLL is 32 or 64 bit
                IMAGE_FILE_HEADER imageFileHeader = CastBytesToType<IMAGE_FILE_HEADER>(sourceFileByteBuffer.Skip(imageDosHeader.e_lfanew + 4).Take(sizeof(IMAGE_FILE_HEADER)).ToArray());

                int sectionOffset = 0;
                int exportOffset = 0;

                if (imageFileHeader.Machine == 0x8664) // 64bit 0x8664
                {

                    // Get IMAGE_NT_HEADER because we need it for address of export table
                    IMAGE_NT_HEADERS64 imageNtHeader = CastBytesToType<IMAGE_NT_HEADERS64>(sourceFileByteBuffer.Skip(imageDosHeader.e_lfanew).Take(sizeof(IMAGE_NT_HEADERS64)).ToArray());

                    // Loop through sections to find where export table resides for section offset (VA - PTRToRawData) use to calculate appropriate file offset

                    int sectionHeadersOffset = imageDosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64);

                    for (int i = 0; i < imageNtHeader.FileHeader.NumberOfSections; i++)
                    {
                        // Parse IMAGE_SECTION_HEADER
                        IMAGE_SECTION_HEADER imageSectionHeader = CastBytesToType<IMAGE_SECTION_HEADER>(sourceFileByteBuffer.Skip(sectionHeadersOffset).Take(SizeOfImageSectionHeader).ToArray());
                        if (imageNtHeader.OptionalHeader.ExportTable.VirtualAddress > imageSectionHeader.VirtualAddress && imageNtHeader.OptionalHeader.ExportTable.VirtualAddress < (imageSectionHeader.VirtualAddress + imageSectionHeader.VirtualSize))
                        {
                            sectionOffset = (int)((imageSectionHeader.VirtualAddress - imageSectionHeader.PointerToRawData));
                            break;
                        }
                        sectionHeadersOffset += SizeOfImageSectionHeader;
                    }

                    // Now that we have offset to turn RVA into a file offset, can get IMAGE_EXPORT_DIRECTORY and start looping through arrays to get exports

                    exportOffset = (int)(imageNtHeader.OptionalHeader.ExportTable.VirtualAddress - sectionOffset);
                }
                else // 32bit
                {
                    IMAGE_NT_HEADERS32 imageNtHeader = CastBytesToType<IMAGE_NT_HEADERS32>(sourceFileByteBuffer.Skip(imageDosHeader.e_lfanew).Take(sizeof(IMAGE_NT_HEADERS32)).ToArray());

                    int sectionHeadersOffset = imageDosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS32);

                    for (int i = 0; i < imageNtHeader.FileHeader.NumberOfSections; i++)
                    {
                        // Parse IMAGE_SECTION_HEADER
                        IMAGE_SECTION_HEADER imageSectionHeader = CastBytesToType<IMAGE_SECTION_HEADER>(sourceFileByteBuffer.Skip(sectionHeadersOffset).Take(SizeOfImageSectionHeader).ToArray());
                        if (imageNtHeader.OptionalHeader.ExportTable.VirtualAddress > imageSectionHeader.VirtualAddress && imageNtHeader.OptionalHeader.ExportTable.VirtualAddress < (imageSectionHeader.VirtualAddress + imageSectionHeader.VirtualSize))
                        {
                            sectionOffset = (int)((imageSectionHeader.VirtualAddress - imageSectionHeader.PointerToRawData));
                            break;
                        }
                        sectionHeadersOffset += SizeOfImageSectionHeader;
                    }

                    // Now that we have offset to turn RVA into a file offset, can get IMAGE_EXPORT_DIRECTORY and start looping through arrays to get exports

                    exportOffset = (int)(imageNtHeader.OptionalHeader.ExportTable.VirtualAddress - sectionOffset);
                }

                IMAGE_EXPORT_DIRECTORY exportTable = CastBytesToType<IMAGE_EXPORT_DIRECTORY>(sourceFileByteBuffer.Skip(exportOffset).Take(sizeof(IMAGE_EXPORT_DIRECTORY)).ToArray());

            // Loop through function names

            try
            {
                int addressOfNamesOffset = (int)(exportTable.AddressOfNames - sectionOffset);
                string[] function_names = new string[exportTable.NumberOfNames];

                for (int i = 0; i < exportTable.NumberOfNames; i++)
                {
                    // Get file offset for function name
                    int nameOffset = BitConverter.ToInt32(sourceFileByteBuffer.Skip(addressOfNamesOffset).Take(4).ToArray(), 0) - sectionOffset;

                    // Get length of the name
                    byte b = 0x01;
                    int nameLength = 0;
                    while (b != 0x00)
                    {
                        b = sourceFileByteBuffer[nameOffset + nameLength];
                        nameLength++;
                    }

                    // Get function name string
                    function_names[i] = System.Text.Encoding.ASCII.GetString(sourceFileByteBuffer.Skip(nameOffset).Take(nameLength).ToArray());
                    addressOfNamesOffset += 4;
                }

                // Loop through ordinals for functions with names

                int ordinalOffset = (int)(exportTable.AddressOfNameOrdinals - sectionOffset);
                short[] ordinals = new short[exportTable.NumberOfNames];
                for (int i = 0; i < exportTable.NumberOfNames; i++)
                {
                    ordinals[i] = (short)(BitConverter.ToInt16(sourceFileByteBuffer, ordinalOffset) + exportTable.Base);
                    ordinalOffset += 2;
                }

                // Loop through functions to get RVA values

                int functionsOffset = (int)(exportTable.AddressOfFunctions - sectionOffset);
                int[] functionRVAs = new int[exportTable.NumberOfFunctions];
                for (int i = 0; i < exportTable.NumberOfFunctions; i++)
                {
                    functionRVAs[i] = BitConverter.ToInt32(sourceFileByteBuffer, functionsOffset);
                    functionsOffset += 4;
                }

            // Print output to mimic dumpbin export output

            
                //Console.WriteLine("\tordinal\thint\tRVA\t\tname");

                for (int i = 0; i < exportTable.NumberOfNames; i++)
                {
                    int function_idx = (int)(ordinals[i] - exportTable.Base);
                    Program.TDllReaderFunc cDllReader = new Program.TDllReaderFunc(function_names[i], DLL);
                    Program.mydata.tdllfunc.Add(cDllReader);

                    Program.Relationship trelation1 = new Program.Relationship(nnid, cDllReader.NodeId, "Export", "ImageLoadName", "DllFunc");
                    Program.mydata.Relationships.Add(trelation1);
                    //Console.WriteLine("\t" + ordinals[i] + "\t" + i.ToString("X") + "\t" + String.Format("{0:X8}", functionRVAs[function_idx]) + "\t" + function_names[i]);
                }

                // Everything without a function name must be a nameless export with an ordinal

                for (int i = 0; i < exportTable.NumberOfFunctions; i++)
                {
                    short ord = (short)(i + exportTable.Base);
                    if (!ordinals.Contains(ord) && functionRVAs[i] != 0)
                    {
                        // Console.WriteLine("\t" + ord + "\t\t" + String.Format("{0:X8}", functionRVAs[i]) + "\t[NONAME]");
                        //string tname = NONAME;
                        //
                        Program.TDllReaderFunc cDllReader = new Program.TDllReaderFunc("NONAME", DLL);
                        Program.mydata.tdllfunc.Add(cDllReader);
                        break;
                        //  Program.TDllReaderFunc cDllReader = new Program.TDllReaderFunc([NONAME]);

                    }
                }
            }
            catch
            {
                Console.WriteLine(" exception reading dll");
                Program.TDllReaderFunc cDllReader = new Program.TDllReaderFunc("NONAME", DLL);
                Program.mydata.tdllfunc.Add(cDllReader);
               // break;
            }

            }
        }
    
}
