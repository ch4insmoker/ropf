#pragma once

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef unsigned long long QWORD;
typedef unsigned long LONG;
typedef signed long long LONGLONG;
typedef unsigned long long ULONGLONG;

#define ROP_IMAGE_NT_OPTIONAL_HDR32_MAGIC       0x10b
#define ROP_IMAGE_NT_OPTIONAL_HDR64_MAGIC       0x20b
#define ROP_IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
#define ROP_IMAGE_DOS_SIGNATURE                 0x5A4D

#define ROP_IMAGE_DIRECTORY_ENTRY_EXPORT          0
#define ROP_IMAGE_DIRECTORY_ENTRY_IMPORT          1
#define ROP_IMAGE_DIRECTORY_ENTRY_RESOURCE        2
#define ROP_IMAGE_DIRECTORY_ENTRY_EXCEPTION       3
#define ROP_IMAGE_DIRECTORY_ENTRY_SECURITY        4
#define ROP_MAGE_DIRECTORY_ENTRY_BASERELOC        5
#define ROP_IMAGE_DIRECTORY_ENTRY_DEBUG           6
#define ROP_IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7
#define ROP_IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8
#define ROP_IMAGE_DIRECTORY_ENTRY_TLS             9
#define ROP_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10
#define ROP_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11
#define ROP_IMAGE_DIRECTORY_ENTRY_IAT            12
#define ROP_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13
#define ROP_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14
#define ROP_IMAGE_SCN_MEM_EXECUTE 0x20000000


#define ROP_IMAGE_SIZEOF_SHORT_NAME              8
#define ROP_IMAGE_SIZEOF_SECTION_HEADER          40

typedef struct __IMAGE_DOS_HEADER {
    WORD   e_magic;
    WORD   e_cblp;
    WORD   e_cp;
    WORD   e_crlc;
    WORD   e_cparhdr;
    WORD   e_minalloc;
    WORD   e_maxalloc;
    WORD   e_ss;
    WORD   e_sp;
    WORD   e_csum;
    WORD   e_ip;
    WORD   e_cs;
    WORD   e_lfarlc;
    WORD   e_ovno;
    WORD   e_res[4];
    WORD   e_oemid;
    WORD   e_oeminfo;
    WORD   e_res2[10];
    LONG   e_lfanew;
} ROP_IMAGE_DOS_HEADER, * ___PIMAGE_DOS_HEADER;

typedef struct __IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} ROP_IMAGE_DATA_DIRECTORY, * ___PIMAGE_DATA_DIRECTORY;


typedef struct __IMAGE_OPTIONAL_HEADER {
    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;
    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    ROP_IMAGE_DATA_DIRECTORY DataDirectory[ROP_IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} ROP_IMAGE_OPTIONAL_HEADER32, * ___PIMAGE_OPTIONAL_HEADER32;

typedef struct __IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    ROP_IMAGE_DATA_DIRECTORY DataDirectory[ROP_IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} ROP_IMAGE_OPTIONAL_HEADER64, * ___PIMAGE_OPTIONAL_HEADER64;

typedef struct __IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} ROP_IMAGE_FILE_HEADER, * ___PIMAGE_FILE_HEADER;

typedef struct __IMAGE_NT_HEADERS64 {
    DWORD Signature;
    ROP_IMAGE_FILE_HEADER FileHeader;
    ROP_IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} ROP_IMAGE_NT_HEADERS64, * ___PIMAGE_NT_HEADERS64;

typedef struct __IMAGE_NT_HEADERS {
    DWORD Signature;
    ROP_IMAGE_FILE_HEADER FileHeader;
    ROP_IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} ROP_IMAGE_NT_HEADERS32, * ___PIMAGE_NT_HEADERS32;

typedef struct __IMAGE_SECTION_HEADER {
    BYTE    Name[ROP_IMAGE_SIZEOF_SHORT_NAME];
    union {
        DWORD   PhysicalAddress;
        DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} ROP_IMAGE_SECTION_HEADER, * ___PIMAGE_SECTION_HEADER;