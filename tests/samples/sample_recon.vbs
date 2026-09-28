' Simulated Defensive Recon Script (COLDRIVER Stage-2 Reconnaissance Lure)
Dim objShell
Set objShell = WScript.CreateObject("WScript.Shell")

' System Discovery and IP Configuration Enumeration
objShell.Run "cmd.exe /c ipconfig /all > %TEMP%\net_config.txt", 0, True

' Process Enumeration
objShell.Run "cmd.exe /c tasklist /v > %TEMP%\proc_list.txt", 0, True

' Network Share Discovery
objShell.Run "cmd.exe /c net view /domain > %TEMP%\shares.txt", 0, True

WScript.Echo "Recon Stage Completed."
