PEchecker
=========

Powershell script to check if a EXE/DLL has been compiled with ASLR, DEP, and SafeSEH.

```
Check a single file

C:\PS> ./PEchecker.ps1 -file C:\Windows\System32\kernel32.dll
```
```
Check a directory for DLLs & EXEs

C:\PS> ./PEchecker.ps1 -directory C:\Windows\System32\
```
```
Check a directory for DLLs & EXEs recrusively

C:\PS> ./PEchecker.ps1 -directory C:\Windows\System32\ -recursive
```
```
Check for only DLLs & EXEs that are not compile with ASLR

C:\PS> ./PEchecker.ps1 -directory C:\Windows\System32\ -recursive -OnlyNoASLR
```
```
Check for only DLLs & EXEs that are not compile with DEP

C:\PS> ./PEchecker.ps1 -directory C:\Windows\System32\ -recursive -OnlyNoDEP
```
```
Check for only DLLs & EXEs that are not compile with SafeSEH

C:\PS> ./PEchecker.ps1 -directory C:\Windows\System32\ -recursive -OnlyNoSafeSEH
```
```
Show results with full path names

C:\PS> ./PEchecker.ps1 -directory C:\Windows\System32\ -recursive
```
```
Export results as a CSV

C:\PS> ./PEchecker.ps1 -directory C:\Windows\System32\ -recursive | Export-CSV file.csv
```
```
Show results in a table

C:\PS> ./PEchecker.ps1 -directory C:\Windows\System32\ -recursive | Format-Table
```
```
Show results in a table and sort by a column

C:\PS> ./PEchecker.ps1 -directory C:\Windows\System32\ -recursive | Format-Table | sort ASLR
```
```
Show results in a list

C:\PS> ./PEchecker.ps1 -directory C:\Windows\System32\ -recursive | Format-List
```
Links

* https://github.com/mattifestation/PowerSploit
* http://msdn.microsoft.com/en-us/library/windows/desktop/ms680336(v=vs.85).aspx
* http://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx
