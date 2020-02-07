<#
  # Author: Eric Gruber 2014, NetSPI
  # Updated: Alex Verboon July 28.2017, added Control Flow Guard information

  .Synopsis
   Updated module to pull security information from compiled Windows binaries.
  .EXAMPLE
   Get-PESecurity -File C:\Windows\System32\cmd.exe
  .EXAMPLE
   Get-PESecurity -Directory C:\Windows\System32\
#>

function Get-PESecurity
{
  [CmdletBinding()]
  Param
  (
    # Directory to scan
    [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
    Position = 0)]
    [String]$Directory,

    # File to scan
    [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $true,
    Position = 0)]
    [String]$File,

    #Recursive flag
    [Parameter(Mandatory = $false,
        ValueFromPipelineByPropertyName = $false,
    Position = 1)]
    [Switch]$Recursive,

    #Skip Authenticode
    [Parameter(Mandatory = $false,
	    ValueFromPipelineByPropertyName = $false,
    Position = 2)]
    [Switch]$SkipAuthenticode

  )

  Begin
  {
    $ModuleName = 'Win32'
    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = [AppDomain]::CurrentDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $Mod = $AssemblyBuilder.DefineDynamicModule($ModuleName, $false)

    $ImageDosSignature = enumerate $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
      DOS_SIGNATURE = 0x5A4D
      OS2_SIGNATURE = 0x454E
      OS2_SIGNATURE_LE = 0x454C
      VXD_SIGNATURE = 0x454C
    }

    $ImageFileMachine = enumerate $Mod PE.IMAGE_FILE_MACHINE UInt16 @{
      UNKNOWN = 0x0000
      I386 = 0x014C # Intel 386.
      R3000 = 0x0162 # MIPS little-endian =0x160 big-endian
      R4000 = 0x0166 # MIPS little-endian
      R10000 = 0x0168 # MIPS little-endian
      WCEMIPSV2 = 0x0169 # MIPS little-endian WCE v2
      ALPHA = 0x0184 # Alpha_AXP
      SH3 = 0x01A2 # SH3 little-endian
      SH3DSP = 0x01A3
      SH3E = 0x01A4 # SH3E little-endian
      SH4 = 0x01A6 # SH4 little-endian
      SH5 = 0x01A8 # SH5
      ARM = 0x01C0 # ARM Little-Endian
      THUMB = 0x01C2
      ARMNT = 0x01C4 # ARM Thumb-2 Little-Endian
      AM33 = 0x01D3
      POWERPC = 0x01F0 # IBM PowerPC Little-Endian
      POWERPCFP = 0x01F1
      IA64 = 0x0200 # Intel 64
      MIPS16 = 0x0266 # MIPS
      ALPHA64 = 0x0284 # ALPHA64
      MIPSFPU = 0x0366 # MIPS
      MIPSFPU16 = 0x0466 # MIPS
      TRICORE = 0x0520 # Infineon
      CEF = 0x0CEF
      EBC = 0x0EBC # EFI public byte Code
      AMD64 = 0x8664 # AMD64 (K8)
      M32R = 0x9041 # M32R little-endian
      CEE = 0xC0EE
    }

    $ImageFileCharacteristics = enumerate $Mod PE.IMAGE_FILE_CHARACTERISTICS UInt16 @{
      IMAGE_RELOCS_STRIPPED = 0x0001 # Relocation info stripped from file.
      IMAGE_EXECUTABLE_IMAGE = 0x0002 # File is executable  (i.e. no unresolved external references).
      IMAGE_LINE_NUMS_STRIPPED = 0x0004 # Line nunbers stripped from file.
      IMAGE_LOCAL_SYMS_STRIPPED = 0x0008 # Local symbols stripped from file.
      IMAGE_AGGRESIVE_WS_TRIM = 0x0010 # Agressively trim working set
      IMAGE_LARGE_ADDRESS_AWARE = 0x0020 # App can handle >2gb addresses
      IMAGE_REVERSED_LO = 0x0080 # public bytes of machine public ushort are reversed.
      IMAGE_32BIT_MACHINE = 0x0100 # 32 bit public ushort machine.
      IMAGE_DEBUG_STRIPPED = 0x0200 # Debugging info stripped from file in .DBG file
      IMAGE_REMOVABLE_RUN_FROM_SWAP = 0x0400 # If Image is on removable media copy and run from the swap file.
      IMAGE_NET_RUN_FROM_SWAP = 0x0800 # If Image is on Net copy and run from the swap file.
      IMAGE_SYSTEM = 0x1000 # System File.
      IMAGE_DLL = 0x2000 # File is a DLL.
      IMAGE_UP_SYSTEM_ONLY = 0x4000 # File should only be run on a UP machine
      IMAGE_REVERSED_HI = 0x8000 # public bytes of machine public ushort are reversed.
    } -Bitfield

    $ImageHdrMagic = enumerate $Mod PE.IMAGE_NT_OPTIONAL_HDR_MAGIC UInt16 @{
      PE32 = 0x010B
      PE64 = 0x020B
    }

    $ImageNTSig = enumerate $Mod PE.IMAGE_NT_SIGNATURE UInt32 @{
      VALID_PE_SIGNATURE = 0x00004550
    }

    $ImageSubsystem = enumerate $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
      UNKNOWN = 0
      NATIVE = 1 # Image doesn't require a subsystem.
      WINDOWS_GUI = 2 # Image runs in the Windows GUI subsystem.
      WINDOWS_CUI = 3 # Image runs in the Windows character subsystem.
      OS2_CUI = 5 # Image runs in the OS/2 character subsystem.
      POSIX_CUI = 7 # Image runs in the Posix character subsystem.
      NATIVE_WINDOWS = 8 # Image is a native Win9x driver.
      WINDOWS_CE_GUI = 9 # Image runs in the Windows CE subsystem.
      EFI_APPLICATION = 10
      EFI_BOOT_SERVICE_DRIVER = 11
      EFI_RUNTIME_DRIVER = 12
      EFI_ROM = 13
      XBOX = 14
      WINDOWS_BOOT_APPLICATION = 16
    }

    $ImageDllCharacteristics = enumerate $Mod PE.IMAGE_DLLCHARACTERISTICS UInt16 @{
      HIGH_ENTROPY_VA = 0x0020 # Opts in to high entropy ASLR
      DYNAMIC_BASE = 0x0040 # DLL can move.
      FORCE_INTEGRITY = 0x0080 # Code Integrity Image
      NX_COMPAT = 0x0100 # Image is NX compatible
      NO_ISOLATION = 0x0200 # Image understands isolation and doesn't want it
      NO_SEH = 0x0400 # Image does not use SEH.  No SE handler may reside in this image
      NO_BIND = 0x0800 # Do not bind this image.
      WDM_DRIVER = 0x2000 # Driver uses WDM model
      GUARD_CF = 0x4000 # Control Flow Guard
      TERMINAL_SERVER_AWARE = 0x8000
    } -Bitfield

    $ImageScn = enumerate $Mod PE.IMAGE_SCN Int32 @{
      TYPE_NO_PAD = 0x00000008 # Reserved.
      CNT_CODE = 0x00000020 # Section contains code.
      CNT_INITIALIZED_DATA = 0x00000040 # Section contains initialized data.
      CNT_UNINITIALIZED_DATA = 0x00000080 # Section contains uninitialized data.
      LNK_INFO = 0x00000200 # Section contains comments or some other type of information.
      LNK_REMOVE = 0x00000800 # Section contents will not become part of image.
      LNK_COMDAT = 0x00001000 # Section contents comdat.
      NO_DEFER_SPEC_EXC = 0x00004000 # Reset speculative exceptions handling bits in the TLB entries for this section.
      GPREL = 0x00008000 # Section content can be accessed relative to GP
      MEM_FARDATA = 0x00008000
      MEM_PURGEABLE = 0x00020000
      MEM_16BIT = 0x00020000
      MEM_LOCKED = 0x00040000
      MEM_PRELOAD = 0x00080000
      ALIGN_1BYTES = 0x00100000
      ALIGN_2BYTES = 0x00200000
      ALIGN_4BYTES = 0x00300000
      ALIGN_8BYTES = 0x00400000
      ALIGN_16BYTES = 0x00500000 # Default alignment if no others are specified.
      ALIGN_32BYTES = 0x00600000
      ALIGN_64BYTES = 0x00700000
      ALIGN_128BYTES = 0x00800000
      ALIGN_256BYTES = 0x00900000
      ALIGN_512BYTES = 0x00A00000
      ALIGN_1024BYTES = 0x00B00000
      ALIGN_2048BYTES = 0x00C00000
      ALIGN_4096BYTES = 0x00D00000
      ALIGN_8192BYTES = 0x00E00000
      ALIGN_MASK = 0x00F00000
      LNK_NRELOC_OVFL = 0x01000000 # Section contains extended relocations.
      MEM_DISCARDABLE = 0x02000000 # Section can be discarded.
      MEM_NOT_CACHED = 0x04000000 # Section is not cachable.
      MEM_NOT_PAGED = 0x08000000 # Section is not pageable.
      MEM_SHARED = 0x10000000 # Section is shareable.
      MEM_EXECUTE = 0x20000000 # Section is executable.
      MEM_READ = 0x40000000 # Section is readable.
      MEM_WRITE = 0x80000000 # Section is writeable.
    } -Bitfield

    $ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
      e_magic = field 0 $ImageDosSignature
      e_cblp = field 1 UInt16
      e_cp = field 2 UInt16
      e_crlc = field 3 UInt16
      e_cparhdr = field 4 UInt16
      e_minalloc = field 5 UInt16
      e_maxalloc = field 6 UInt16
      e_ss = field 7 UInt16
      e_sp = field 8 UInt16
      e_csum = field 9 UInt16
      e_ip = field 10 UInt16
      e_cs = field 11 UInt16
      e_lfarlc = field 12 UInt16
      e_ovno = field 13 UInt16
      e_res = field 14 UInt16[] -MarshalAs @('ByValArray', 4)
      e_oemid = field 15 UInt16
      e_oeminfo = field 16 UInt16
      e_res2 = field 17 UInt16[] -MarshalAs @('ByValArray', 10)
      e_lfanew = field 18 Int32
    }

    $ImageFileHeader = struct $Mod PE.IMAGE_FILE_HEADER @{
      Machine = field 0 $ImageFileMachine
      NumberOfSections = field 1 UInt16
      TimeDateStamp = field 2 UInt32
      PointerToSymbolTable = field 3 UInt32
      NumberOfSymbols = field 4 UInt32
      SizeOfOptionalHeader = field 5 UInt16
      Characteristics = field 6 $ImageFileCharacteristics
    }

    $PeImageDataDir = struct $Mod PE.IMAGE_DATA_DIRECTORY @{
      VirtualAddress = field 0 UInt32
      Size = field 1 UInt32
    }

    $ImageOptionalHdr = struct $Mod PE.IMAGE_OPTIONAL_HEADER @{
      Magic = field 0 $ImageHdrMagic
      MajorLinkerVersion = field 1 Byte
      MinorLinkerVersion = field 2 Byte
      SizeOfCode = field 3 UInt32
      SizeOfInitializedData = field 4 UInt32
      SizeOfUninitializedData = field 5 UInt32
      AddressOfEntryPoint = field 6 UInt32
      BaseOfCode = field 7 UInt32
      BaseOfData = field 8 UInt32
      ImageBase = field 9 UInt32
      SectionAlignment = field 10 UInt32
      FileAlignment = field 11 UInt32
      MajorOperatingSystemVersion = field 12 UInt16
      MinorOperatingSystemVersion = field 13 UInt16
      MajorImageVersion = field 14 UInt16
      MinorImageVersion = field 15 UInt16
      MajorSubsystemVersion = field 16 UInt16
      MinorSubsystemVersion = field 17 UInt16
      Win32VersionValue = field 18 UInt32
      SizeOfImage = field 19 UInt32
      SizeOfHeaders = field 20 UInt32
      CheckSum = field 21 UInt32
      Subsystem = field 22 $ImageSubsystem
      DllCharacteristics = field 23 $ImageDllCharacteristics
      SizeOfStackReserve = field 24 UInt32
      SizeOfStackCommit = field 25 UInt32
      SizeOfHeapReserve = field 26 UInt32
      SizeOfHeapCommit = field 27 UInt32
      LoaderFlags = field 28 UInt32
      NumberOfRvaAndSizes = field 29 UInt32
      DataDirectory = field 30 $PeImageDataDir.MakeArrayType() -MarshalAs @('ByValArray', 16)
    }

    $ImageOptionalHdr64 = struct $Mod PE.IMAGE_OPTIONAL_HEADER64 @{
      Magic = field 0 $ImageHdrMagic
      MajorLinkerVersion = field 1 Byte
      MinorLinkerVersion = field 2 Byte
      SizeOfCode = field 3 UInt32
      SizeOfInitializedData = field 4 UInt32
      SizeOfUninitializedData = field 5 UInt32
      AddressOfEntryPoint = field 6 UInt32
      BaseOfCode = field 7 UInt32
      ImageBase = field 8 UInt64
      SectionAlignment = field 9 UInt32
      FileAlignment = field 10 UInt32
      MajorOperatingSystemVersion = field 11 UInt16
      MinorOperatingSystemVersion = field 12 UInt16
      MajorImageVersion = field 13 UInt16
      MinorImageVersion = field 14 UInt16
      MajorSubsystemVersion = field 15 UInt16
      MinorSubsystemVersion = field 16 UInt16
      Win32VersionValue = field 17 UInt32
      SizeOfImage = field 18 UInt32
      SizeOfHeaders = field 19 UInt32
      CheckSum = field 20 UInt32
      Subsystem = field 21 $ImageSubsystem
      DllCharacteristics = field 22 $ImageDllCharacteristics
      SizeOfStackReserve = field 23 UInt64
      SizeOfStackCommit = field 24 UInt64
      SizeOfHeapReserve = field 25 UInt64
      SizeOfHeapCommit = field 26 UInt64
      LoaderFlags = field 27 UInt32
      NumberOfRvaAndSizes = field 28 UInt32
      DataDirectory = field 29 $PeImageDataDir.MakeArrayType() -MarshalAs @('ByValArray', 16)
    }

    $ImageSectionHdrs = struct $Mod PE.IMAGE_SECTION_HEADER @{
      Name = field 0 String -MarshalAs @('ByValTStr', 8)
      VirtualSize = field 1 UInt32
      VirtualAddress = field 2 UInt32
      SizeOfRawData = field 3 UInt32
      PointerToRawData = field 4 UInt32
      PointerToRelocations = field 5 UInt32
      PointerToLinenumbers = field 6 UInt32
      NumberOfRelocations = field 7 UInt16
      NumberOfLinenumbers = field 8 UInt16
      Characteristics = field 9 $ImageScn
    }

    $ImageConfigDirectory = struct $Mod PE.IMAGE_LOAD_CONFIG_DIRECTORY @{
      Size = field 0 UInt32
      TimeDateStamp = field 1 UInt32
      MajorVersion = field 2 UInt16
      MinorVersion = field 3 UInt16
      GlobalFlagsClear = field 4 UInt32
      GlobalFlagsSet = field 5 UInt32
      CriticalSectionDefaultTimeout = field 6 UInt32
      DeCommitFreeBlockThreshold = field 7 UInt32
      DeCommitTotalFreeThreshold = field 8 UInt32
      LockPrefixTable = field 9 UInt32
      MaximumAllocationSize = field 10 UInt32
      VirtualMemoryThreshold = field 11 UInt32
      ProcessHeapFlags = field 12 UInt32
      ProcessAffinityMask = field 13 UInt32
      CSDVersion = field 14 UInt16
      Reserved1 = field 15 UInt16
      EditList = field 16 UInt32
      SecurityCookie = field 17 UInt32
      SEHandlerTable = field 18 UInt32
      SEHandlerCount = field 19 UInt32
    }

    $ImageNTHdrs = struct $Mod PE.IMAGE_NT_HEADERS @{
      Signature = field 0 $ImageNTSig
      FileHeader = field 1 $ImageFileHeader
      OptionalHeader = field 2 $ImageOptionalHdr
    }

    $ImageNTHdrs64 = struct $Mod PE.IMAGE_NT_HEADERS64 @{
      Signature = field 0 $ImageNTSig
      FileHeader = field 1 $ImageFileHeader
      OptionalHeader = field 2 $ImageOptionalHdr64
    }

    $FunctionDefinitions = @(
      (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String])),
      (func kernel32 GetModuleHandle ([Intptr]) @([String])),
      (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
    )

    $Table = New-Object system.Data.DataTable 'table'
    $Col1 = New-Object system.Data.DataColumn FileName, ([string])
    $Col2 = New-Object system.Data.DataColumn ARCH, ([string])
    $Col3 = New-Object system.Data.DataColumn DotNET, ([string])
    $Col4 = New-Object system.Data.DataColumn ASLR, ([string])
    $Col5 = New-Object system.Data.DataColumn DEP, ([string])
    $Col6 = New-Object system.Data.DataColumn Authenticode, ([string])
    $Col7 = New-Object system.Data.DataColumn StrongNaming, ([string])
    $Col8 = New-Object system.Data.DataColumn SafeSEH, ([string])
    $Col9 = New-Object system.Data.DataColumn ControlFlowGuard, ([string])
    $Col10 = New-Object system.Data.DataColumn HighentropyVA, ([string])
    $Table.columns.add($Col1)
    $Table.columns.add($Col2)
    $Table.columns.add($Col3)
    $Table.columns.add($Col4)
    $Table.columns.add($Col5)
    $Table.columns.add($Col6)
    $Table.columns.add($Col7)
    $Table.columns.add($Col8)
    $Table.columns.add($Col9)
    $Table.columns.add($Col10)
  }
  Process
  {
    $Files = Get-Files
    Enumerate-Files $Files $Table

    $Table
  }
  End
  {
  }
}

function Enumerate-Files
{
  param
  (
    [System.Object]
    $Files,

    [System.Object]
    $Table
  )

  foreach ($CurrentFile in $Files)
  {
    $DotNET = $false
    $ASLR = $false
    $HighentropyVA = $false
    $DEP = $false
    $SEH = $false
    $ControlFlowGuard = $false
    $Authenticode = $false
    $StrongNaming = $false

    # Determine file length
    $FileInfo = New-Object System.IO.FileInfo($CurrentFile)
    $FileLength = $FileInfo.length
    # Read the bytes
    $FileStream = New-Object System.IO.FileStream($CurrentFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
    $BinaryReader = New-Object System.IO.BinaryReader($FileStream)
    # Pull a maximum of 1024 bytes from the file
    $BytesToRead = [Math]::Min($FileLength, 1024)
    # Read
    $FileByteArray = $BinaryReader.ReadBytes( $BytesToRead )
    # Cleanup
    $BinaryReader.Close()
    $FileStream.Close()

    $Handle = [System.Runtime.InteropServices.GCHandle]::Alloc($FileByteArray, 'Pinned')
    $PEBaseAddr = $Handle.AddrOfPinnedObject()
    $DosHeader = $PEBaseAddr -as $ImageDosHeader
    if ($FileByteArray.Length -lt $DosHeader.e_lfanew)
    {
      continue
    }
    $PointerNtHeader = [IntPtr] ($PEBaseAddr.ToInt64() + $DosHeader.e_lfanew)
    $NTHeader = $PointerNtHeader -as $ImageNTHdrs
    if ($NTHeader.OptionalHeader.Magic -eq 0){
        $Row = $Table.NewRow()
        $Row.FileName = $CurrentFile
        $Row.ARCH = 'Unknown Format'
        $Row.DotNET = 'Unknown Format'
        $Row.ASLR = 'Unknown Format'
        $Row.HighentropyVA = 'Unknown Format'
        $Row.DEP = 'Unknown Format'
        $Row.Authenticode = 'Unknown Format'
        $Row.StrongNaming = 'Unknown Format'
        $Row.SafeSEH = 'Unknown Format'
        $Row.ControlFlowGuard = 'Unknown Format'
        $Table.Rows.Add($Row)
        Continue
    }
    if ($NTHeader.OptionalHeader.Magic -eq 'PE64')
    {
      $NTHeader = $PointerNtHeader -as $ImageNTHdrs64
    }

    if($NTHeader.OptionalHeader.DataDirectory[14].VirtualAddress -ne 0) {
      $DotNet = $true
    }

    $ARCH = $NTHeader.FileHeader.Machine.toString()
    $FileCharacteristics = $NTHeader.FileHeader.Characteristics.toString().Split(',')
    $DllCharacteristics = $NTHeader.OptionalHeader.DllCharacteristics.toString().Split(',')
    $value = 0
    $ASLR = $false
    if([int32]::TryParse($DllCharacteristics, [ref]$value)){
        if($value -band 0x20){
            $HighentropyVA = $true
        }
        if($value -band 0x40){
            $ASLR = $true
        }
        if($value -band 0x100){
            $DEP = $true
        }

        if($value -band 0x400){
            $SEH = 'N/A'
        }

        if($value -band 0x4000){
            $ControlFlowGuard = $true
        }
    } else {
      foreach($DllCharacteristic in $DllCharacteristics)
      {
        switch($DllCharacteristic.Trim()){
          'DYNAMIC_BASE'
          {
            $ASLR = $true
          }
          'NX_COMPAT'
          {
            $DEP = $true
          }
          'NO_SEH'
          {
            $SEH = 'N/A'
          }
          'GUARD_CF'
          {
            $ControlFlowGuard = $true
          }
          'HIGH_ENTROPY_VA'
          {
            $HighentropyVA = $true
          }
        }
      }
    }

    if($ASLR){
      foreach($FileCharacteristic in $FileCharacteristics){
        switch($FileCharacteristic.Trim()){
          'IMAGE_RELOCS_STRIPPED'
          {
            $Stripped = $true
          }
        }
      }

      $OS = [Environment]::OSVersion
      $WindowsCheck = $true
      if($OS.Version.Build -ge 9200){
        $WindowsCheck = $false
      }

      if($WindowsCheck){
        if (-not $DotNet -and $Stripped){
          $ASLR = 'False (DYNAMICBASE Set And Relocation Table Stripped)'
        }
      }
    }

    #Get Strongnaming Status
    $StrongNaming = Get-StrongNamingStatus $CurrentFile

    #Get Authenticode Status
	$Authenticode = 'N/A'
	if(!$SkipAuthenticode)
	{
		$Authenticode = Get-AuthenticodeStatus $CurrentFile
	}

    if ($ARCH -eq 'AMD64')
    {
      $SEH = 'N/A'
    }
    elseif ($SEH -ne 'N/A')
    {
      #Get SEH Status
      $SEH = Get-SEHStatus $CurrentFile $NTHeader $PointerNtHeader $PEBaseAddr
    }

    #Write everything to a DataTable
    $Row = $Table.NewRow()
    $Row.FileName = $CurrentFile
    $Row.ARCH = $ARCH
    $Row.DotNET = $DotNET
    $Row.ASLR = $ASLR
    $Row.DEP = $DEP
    $Row.Authenticode = $Authenticode
    $Row.StrongNaming = $StrongNaming
    $Row.SafeSEH = $SEH
    $Row.ControlFlowGuard = $ControlFlowGuard
    $Row.HighentropyVA = $HighentropyVA
    $Table.Rows.Add($Row)
  }
}

function Get-AuthenticodeStatus
{
  param
  (
    [System.Object]
    $CurrentFile

  )

  $Status = Get-AuthenticodeSignature $CurrentFile | Select-Object -ExpandProperty Status

  if ($Status -eq 'Valid')
  {
    $Authenticode = $true
  }
  else
  {
    $Authenticode = $false
  }
  $Authenticode
}

function Get-SEHStatus
{
  param
  (
    [System.Object]
    $CurrentFile,

    [System.Object]
    $NTHeader,

    [System.Object]
    $PointerNtHeader,

    [System.Object]
    $PEBaseAddr
  )
  $NumSections = $NTHeader.FileHeader.NumberOfSections
  $PointerSectionHeader = [IntPtr] ($PointerNtHeader.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf([System.Type] $ImageNTHdrs))
  #Create an array of SectionHeaders
  $SectionHeaders = @(New-Object $ImageSectionHdrs) * $NumSections

  foreach ($i in 0..($NumSections - 1))
  {
    $SectionHeaders[$i] = [System.Runtime.InteropServices.Marshal]::PtrToStructure(([IntPtr] ($PointerSectionHeader.ToInt64() + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([System.Type] $ImageSectionHdrs)))), [System.Type] $ImageSectionHdrs)
  }
  $ConfigPointer = [IntPtr] ($PEBaseAddr.ToInt64() + $NTHeader.OptionalHeader.DataDirectory[10].VirtualAddress)
  $ConfigPointer = Convert-RVAToFileOffset $ConfigPointer $SectionHeaders $PEBaseAddr
  $ConfigDirectory = [System.Runtime.InteropServices.Marshal]::PtrToStructure([IntPtr] $ConfigPointer, [System.Type] $ImageConfigDirectory)
  $SEHandlerTable = $ConfigDirectory.SEHandlerTable
  $SEHandlerCount = $ConfigDirectory.SEHandlerCount
  if($NTHeader.OptionalHeader.DataDirectory[10].VirtualAddress -eq 0)
  {
    $SEH = $false
  }
  elseif($ConfigDirectory.Size -lt 72)
  {
    $SEH = $false
  }
  elseif($SEHandlerTable -ne 0 -and $SEHandlerCount -ne 0)
  {
    $SEH = $true
  }
  elseif($SEHandlerTable -eq 0 -or $SEHandlerCount -eq 0)
  {
    $SEH = $false
  }
  $SEH
}

function Get-StrongNamingStatus
{
  param
  (
    [System.Object]
    $CurrentFile
  )

  try
  {
    $StongNaming = [System.Reflection.AssemblyName]::GetAssemblyName($CurrentFile).GetPublicKeyToken().Count -gt 0
  }
  catch
  {
    $StongNaming = 'N/A'
  }
  $StongNaming
}

function Get-GS {
}

function Get-Files
{
  $Files = @()
  if($Directory)
  {
    $Files += Get-FilesFromDirectory
  }
  if($File)
  {
    $Files += Get-ChildItem $File
  }
  $Files
}

function Get-FilesFromDirectory
{
  if($Recursive)
  {
    Get-ChildItem -Path "$Directory\*" -Recurse -Include *.exe, *.dll | ForEach-Object {
      $Files += $_
    }
  }
  else
  {
    Get-ChildItem -Path "$Directory\*" -Include *.exe, *.dll |ForEach-Object {
      $Files += $_
    }
  }
  $Files
}

function Convert-RVAToFileOffset
{
  #Author: Matthew Graeber (@mattifestation)
  param
  (
    [IntPtr]
    $Rva
  )

  foreach ($Section in $SectionHeaders)
  {
    if ((($Rva.ToInt64() - $PEBaseAddr.ToInt64()) -ge $Section.VirtualAddress) -and (($Rva.ToInt64() - $PEBaseAddr.ToInt64()) -lt ($Section.VirtualAddress + $Section.VirtualSize)))
    {
      return [IntPtr] ($Rva.ToInt64() - ($Section.VirtualAddress - $Section.PointerToRawData))
      Write-Host $Section
    }
  }

  $Rva
}

<#
  The following functions are from Matt Graeber's method of PSReflection
  https://github.com/mattifestation/PSReflect
#>

function func
{
  #Author: Matthew Graeber (@mattifestation)
  Param
  (
    [Parameter(Position = 0, Mandatory = $true)]
    [String]
    $DllName,

    [Parameter(Position = 1, Mandatory = $true)]
    [string]
    $FunctionName,

    [Parameter(Position = 2, Mandatory = $true)]
    [Type]
    $ReturnType,

    [Parameter(Position = 3)]
    [Type[]]
    $ParameterTypes,

    [Parameter(Position = 4)]
    [Runtime.InteropServices.CallingConvention]
    $NativeCallingConvention,

    [Parameter(Position = 5)]
    [Runtime.InteropServices.CharSet]
    $Charset,

    [Switch]
    $SetLastError
  )

  $Properties = @{
    DllName = $DllName
    FunctionName = $FunctionName
    ReturnType = $ReturnType
  }

  if ($ParameterTypes)
  {
    $Properties['ParameterTypes'] = $ParameterTypes
  }
  if ($NativeCallingConvention)
  {
    $Properties['NativeCallingConvention'] = $NativeCallingConvention
  }
  if ($Charset)
  {
    $Properties['Charset'] = $Charset
  }
  if ($SetLastError)
  {
    $Properties['SetLastError'] = $SetLastError
  }

  New-Object PSObject -Property $Properties
}

function enumerate
{
  <#
    Author: Matthew Graeber (@mattifestation)
    .SYNOPSIS

    Creates an in-memory enumeration for use in your PowerShell session.

    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .DESCRIPTION

    The 'enum' function facilitates the creation of enums entirely in
    memory using as close to a "C style" as PowerShell will allow.

    .PARAMETER Module

    The in-memory module that will host the enum. Use
    New-InMemoryModule to define an in-memory module.

    .PARAMETER FullName

    The fully-qualified name of the enum.

    .PARAMETER Type

    The type of each enum element.

    .PARAMETER EnumElements

    A hashtable of enum elements.

    .PARAMETER Bitfield

    Specifies that the enum should be treated as a bitfield.

    .EXAMPLE

    $Mod = New-InMemoryModule -ModuleName Win32

    $ImageSubsystem = enum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn't require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
    }

    .NOTES

    PowerShell purists may disagree with the naming of this function but
    again, this was developed in such a way so as to emulate a "C style"
    definition as closely as possible. Sorry, I'm not going to name it
    New-Enum. :P
  #>

  [OutputType([Type])]
  Param
  (
    [Parameter(Position = 0, Mandatory = $true)]
    [Reflection.Emit.ModuleBuilder]
    $Module,

    [Parameter(Position = 1, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]
    $FullName,

    [Parameter(Position = 2, Mandatory = $true)]
    [Type]
    $Type,

    [Parameter(Position = 3, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [Hashtable]
    $EnumElements,

    [Switch]
    $Bitfield
  )

  $EnumType = $Type -as [Type]

  $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

  if ($Bitfield)
  {
    $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
    $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
    $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
  }

  foreach ($Key in $EnumElements.Keys)
  {
    # Apply the specified enum type to each element
    $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
  }

  $EnumBuilder.CreateType()
}

function struct
{
  <#
    Author: Matthew Graeber (@mattifestation)
    .SYNOPSIS

    Creates an in-memory struct for use in your PowerShell session.

    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: field

    .DESCRIPTION

    The 'struct' function facilitates the creation of structs entirely in
    memory using as close to a "C style" as PowerShell will allow. Struct
    fields are specified using a hashtable where each field of the struct
    is comprosed of the order in which it should be defined, its .NET
    type, and optionally, its offset and special marshaling attributes.

    One of the features of 'struct' is that after your struct is defined,
    it will come with a built-in GetSize method as well as an explicit
    converter so that you can easily cast an IntPtr to the struct without
    relying upon calling SizeOf and/or PtrToStructure in the Marshal
    class.

    .PARAMETER Module

    The in-memory module that will host the struct. Use
    New-InMemoryModule to define an in-memory module.

    .PARAMETER FullName

    The fully-qualified name of the struct.

    .PARAMETER StructFields

    A hashtable of fields. Use the 'field' helper function to ease
    defining each field.

    .PARAMETER PackingSize

    Specifies the memory alignment of fields.

    .PARAMETER ExplicitLayout

    Indicates that an explicit offset for each field will be specified.

    .EXAMPLE

    $Mod = New-InMemoryModule -ModuleName Win32

    $ImageDosSignature = enum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
    }

    $ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
    }

    # Example of using an explicit layout in order to create a union.
    $TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
    } -ExplicitLayout

    .NOTES

    PowerShell purists may disagree with the naming of this function but
    again, this was developed in such a way so as to emulate a "C style"
    definition as closely as possible. Sorry, I'm not going to name it
    New-Struct. :P
  #>
  [OutputType([Type])]
  Param
  (
    [Parameter(Position = 1, Mandatory = $true)]
    [Reflection.Emit.ModuleBuilder]
    $Module,

    [Parameter(Position = 2, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]
    $FullName,

    [Parameter(Position = 3, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [Hashtable]
    $StructFields,

    [Reflection.Emit.PackingSize]
    $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

    [Switch]
    $ExplicitLayout
  )

  [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
    Class,
    Public,
    Sealed,
  BeforeFieldInit'

  if ($ExplicitLayout)
  {
    $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
  }
  else
  {
    $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
  }

  $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
  $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
  $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

  $Fields = New-Object Hashtable[]($StructFields.Count)

  # Sort each field according to the orders specified
  # Unfortunately, PSv2 doesn't have the luxury of the
  # hashtable [Ordered] accelerator.
  foreach ($Field in $StructFields.Keys)
  {
    $Index = $StructFields[$Field]['Position']
    $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
  }

  foreach ($Field in $Fields)
  {
    $FieldName = $Field['FieldName']
    $FieldProp = $Field['Properties']

    $Offset = $FieldProp['Offset']
    $Type = $FieldProp['Type']
    $MarshalAs = $FieldProp['MarshalAs']

    $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

    if ($MarshalAs)
    {
      $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
      $Size = $MarshalAs[1]
      $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
      $UnmanagedType, $SizeConst, @($Size))
      $NewField.SetCustomAttribute($AttribBuilder)
    }

    if ($ExplicitLayout)
    {
      $NewField.SetOffset($Offset)
    }
  }

  # Make the struct aware of its own size.
  # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
  $SizeMethod = $StructBuilder.DefineMethod('GetSize',
    'Public, Static',
    [Int],
  [Type[]] @())
  $ILGenerator = $SizeMethod.GetILGenerator()
  # Thanks for the help, Jason Shirk!
  $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
  $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
  [Type].GetMethod('GetTypeFromHandle'))
  $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
  [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
  $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

  # Allow for explicit casting from an IntPtr
  # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
  $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
    'PrivateScope, Public, Static, HideBySig, SpecialName',
    $StructBuilder,
  [Type[]] @([IntPtr]))
  $ILGenerator2 = $ImplicitConverter.GetILGenerator()
  $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
  $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
  $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
  $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
  [Type].GetMethod('GetTypeFromHandle'))
  $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
  [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
  $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
  $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

  $StructBuilder.CreateType()
}

function field
{
  #Author: Matthew Graeber (@mattifestation)
  Param
  (
    [Parameter(Position = 0, Mandatory = $true)]
    [UInt16]
    $Position,

    [Parameter(Position = 1, Mandatory = $true)]
    [Type]
    $Type,

    [Parameter(Position = 2)]
    [UInt16]
    $Offset,

    [Object[]]
    $MarshalAs
  )

  @{
    Position = $Position
    Type = $Type -as [Type]
    Offset = $Offset
    MarshalAs = $MarshalAs
  }
}

function Add-Win32Type
{
  <#
    Author: Matthew Graeber (@mattifestation)
    .SYNOPSIS

    Creates a .NET type for an unmanaged Win32 function.

    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: func

    .DESCRIPTION

    Add-Win32Type enables you to easily interact with unmanaged (i.e.
    Win32 unmanaged) functions in PowerShell. After providing
    Add-Win32Type with a function signature, a .NET type is created
    using reflection (i.e. csc.exe is never called like with Add-Type).

    The 'func' helper function can be used to reduce typing when defining
    multiple function definitions.

    .PARAMETER DllName

    The name of the DLL.

    .PARAMETER FunctionName

    The name of the target function.

    .PARAMETER ReturnType

    The return type of the function.

    .PARAMETER ParameterTypes

    The function parameters.

    .PARAMETER NativeCallingConvention

    Specifies the native calling convention of the function. Defaults to
    stdcall.

    .PARAMETER Charset

    If you need to explicitly call an 'A' or 'W' Win32 function, you can
    specify the character set.

    .PARAMETER SetLastError

    Indicates whether the callee calls the SetLastError Win32 API
    function before returning from the attributed method.

    .PARAMETER Module

    The in-memory module that will host the functions. Use
    New-InMemoryModule to define an in-memory module.

    .PARAMETER Namespace

    An optional namespace to prepend to the type. Add-Win32Type defaults
    to a namespace consisting only of the name of the DLL.

    .EXAMPLE

    $Mod = New-InMemoryModule -ModuleName Win32

    $FunctionDefinitions = @(
    (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
    (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
    (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
    )

    $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
    $Kernel32 = $Types['kernel32']
    $Ntdll = $Types['ntdll']
    $Ntdll::RtlGetCurrentPeb()
    $ntdllbase = $Kernel32::GetModuleHandle('ntdll')
    $Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

    .NOTES

    Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

    When defining multiple function prototypes, it is ideal to provide
    Add-Win32Type with an array of function signatures. That way, they
    are all incorporated into the same in-memory module.
  #>
  [OutputType([Hashtable])]
  Param(
    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
    [String]
    $DllName,

    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
    [String]
    $FunctionName,

    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
    [Type]
    $ReturnType,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [Type[]]
    $ParameterTypes,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [Runtime.InteropServices.CallingConvention]
    $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [Runtime.InteropServices.CharSet]
    $Charset = [Runtime.InteropServices.CharSet]::Auto,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [Switch]
    $SetLastError,

    [Parameter(Mandatory = $true)]
    [Reflection.Emit.ModuleBuilder]
    $Module,

    [ValidateNotNull()]
    [String]
    $Namespace = ''
  )

  BEGIN
  {
    $TypeHash = @{}
  }

  PROCESS
  {
    # Define one type for each DLL
    if (!$TypeHash.ContainsKey($DllName))
    {
      if ($Namespace)
      {
        $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
      }
      else
      {
        $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
      }
    }

    $Method = $TypeHash[$DllName].DefineMethod(
      $FunctionName,
      'Public,Static,PinvokeImpl',
      $ReturnType,
    $ParameterTypes)

    # Make each ByRef parameter an Out parameter
    $i = 1
    foreach($Parameter in $ParameterTypes)
    {
      if ($Parameter.IsByRef)
      {
        [void] $Method.DefineParameter($i, 'Out', $null)
      }

      $i++
    }

    $DllImport = [Runtime.InteropServices.DllImportAttribute]
    $SetLastErrorField = $DllImport.GetField('SetLastError')
    $CallingConventionField = $DllImport.GetField('CallingConvention')
    $CharsetField = $DllImport.GetField('CharSet')
    if ($SetLastError)
    {
      $SLEValue = $true
    }
    else
    {
      $SLEValue = $false
    }

    # Equivalent to C# version of [DllImport(DllName)]
    $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
    $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
      $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
      [Reflection.FieldInfo[]] @($SetLastErrorField, $CallingConventionField, $CharsetField),
    [Object[]] @($SLEValue, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))

    $Method.SetCustomAttribute($DllImportAttribute)
  }

  END
  {
    $ReturnTypes = @{}

    foreach ($Key in $TypeHash.Keys)
    {
      $Type = $TypeHash[$Key].CreateType()

      $ReturnTypes[$Key] = $Type
    }

    return $ReturnTypes
  }
}

Export-ModuleMember -Function Get-PESecurity
