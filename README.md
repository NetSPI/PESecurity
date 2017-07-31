PESecurity
=========

PowerShell script to check if a Windows binary (EXE/DLL) has been compiled with ASLR, DEP, SafeSEH, StrongNaming, Authenticode, Control Flow Guard, and HighEntropyVA.

```
Import the module

Import-Module .\Get-PESecurity.psm1
```

```
Check a single file

C:\PS> Get-PESecurity -file C:\Windows\System32\kernel32.dll
```
![alt tag](https://blog.netspi.com/wp-content/uploads/2015/04/1430244761-63bc99d7c54f20ad054c16a57024c1f0.jpg)
```
Check a directory for DLLs & EXEs

C:\PS> Get-PESecurity -directory C:\Windows\System32\
```
![alt tag](https://blog.netspi.com/wp-content/uploads/2015/04/1430244799-241f7fa19b34bcdb3133a4544febb15e.jpg)
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
![alt tag](https://blog.netspi.com/wp-content/uploads/2015/04/1430244822-ab1bfbed9031056d57f07d32955ef5b6.jpg)
```
Show results in a table and sort by a column

C:\PS> Get-PESecurity -directory C:\Windows\System32\ -recursive | Format-Table | sort ASLR
```
Links

* http://msdn.microsoft.com/en-us/library/windows/desktop/ms680336(v=vs.85).aspx
* http://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx
* http://msdn.microsoft.com/en-us/library/windows/desktop/ms680328(v=vs.85).aspx
* http://msdn.microsoft.com/en-us/library/9a89h429.aspx
* https://github.com/mattifestation/PowerSploit
