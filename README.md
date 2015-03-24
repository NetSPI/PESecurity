PEchecker
=========

PowerShell script to check if an image (EXE/DLL) has been compiled with ASLR, DEP, SafeSEH, StrongNaming, and Authenticode.

```
Import the module

Import-Module .\Get-PESecurity.psm1
```

```
Check a single file

C:\PS> Get-PESecurity -file C:\Windows\System32\kernel32.dll
```
```
Check a directory for DLLs & EXEs

C:\PS> Get-PESecurity -directory C:\Windows\System32\
```
```
Check a directory for DLLs & EXEs recrusively

C:\PS> Get-PESecurity -directory C:\Windows\System32\ -recursive
```
```
Export results as a CSV

C:\PS>  Get-PESecurity -directory C:\Windows\System32\ -recursive | Export-CSV file.csv
```
```
Show results in a table

C:\PS> Get-PESecurity -directory C:\Windows\System32\ -recursive | Format-Table
```
```
Show results in a table and sort by a column

C:\PS> Get-PESecurity -directory C:\Windows\System32\ -recursive | Format-Table | sort ASLR
```
```
Show results in a list

C:\PS> Get-PESecurity -directory C:\Windows\System32\ -recursive | Format-List
```
Links

* http://msdn.microsoft.com/en-us/library/windows/desktop/ms680336(v=vs.85).aspx
* http://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx
* http://msdn.microsoft.com/en-us/library/windows/desktop/ms680328(v=vs.85).aspx
* http://msdn.microsoft.com/en-us/library/9a89h429.aspx
* https://github.com/mattifestation/PowerSploit
