@echo off
ver | find "Version 6.1" > nul
IF %ERRORLEVEL% == 0 (
       echo win2008r2detected
       IF "%PROCESSOR_ARCHITECTURE%" == "x86" (
             echo x86install
                XCOPY "\\srv1\Distrib\OSA\Microsoft\Net Framework\NDP452-KB2901907-x86-x64-AllOS-ENU.exe" "C:\Temp\" /Y /Q
             XCOPY "\\srv1\Distrib\OSA\Microsoft\PowerShell\Windows Management Framework [4.0]\Windows6.1-KB2819745-x64-MultiPkg.msu" "C:\Temp\" /Y /Q
             cd "C:\Temp"
             start /wait NDP452-KB2901907-x86-x64-AllOS-ENU.exe /quiet /norestart
             start /wait Windows6.1-KB2819745-x64-MultiPkg.msu/quiet /forcerestart
       ) ELSE (
             echo x64install
             XCOPY "\\srv1\Distrib\OSA\Microsoft\Net Framework\NDP452-KB2901907-x86-x64-AllOS-ENU.exe" "C:\Temp\" /Y /Q
             XCOPY "\\srv1\Distrib\OSA\Microsoft\PowerShell\Windows Management Framework [4.0]\Windows6.1-KB2819745-x86-MultiPkg.msu" "C:\Temp\" /Y /Q
             cd "C:\Temp"
             start /wait NDP452-KB2901907-x86-x64-AllOS-ENU.exe /quiet /norestart
             start /wait Windows6.1-KB2819745-x86-MultiPkg.msu /quiet /forcerestart

       )
)
echo finish
cmd /c  %SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe -command "&{Set-executionpolicy unrestricted -Confirm:$false}"
%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe -command $psversiontable.PSVersion.Major
