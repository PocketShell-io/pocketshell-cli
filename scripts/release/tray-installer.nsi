Unicode true
Name "PocketShell Gateway"
OutFile "${OUTPUT}"
InstallDir "$LOCALAPPDATA\Programs\PocketShellGateway"
RequestExecutionLevel user
SetCompressor /SOLID lzma
SetCompressorDictSize 64
ShowInstDetails show
ShowUninstDetails show
Page directory
Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

Section "PocketShell Gateway"
  SetOutPath "$INSTDIR"
  File /r "${PAYLOAD}\*.*"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateDirectory "$SMPROGRAMS\PocketShell Gateway"
  CreateShortcut "$SMPROGRAMS\PocketShell Gateway\PocketShell Gateway.lnk" "$INSTDIR\runtime\GatewayTray.exe"
  CreateShortcut "$SMPROGRAMS\PocketShell Gateway\Gateway Setup.lnk" "$INSTDIR\runtime\GatewayTray.exe" "--setup"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "PocketShellTray" '$\"$INSTDIR\runtime\GatewayTray.exe$\"'
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\PocketShellGateway" "DisplayName" "PocketShell Gateway"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\PocketShellGateway" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\PocketShellGateway" "UninstallString" '$\"$INSTDIR\Uninstall.exe$\"'
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\PocketShellGateway" "NoModify" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\PocketShellGateway" "NoRepair" 1
SectionEnd

Function .onInstSuccess
  IfSilent done
  ExecShell "open" "$INSTDIR\runtime\GatewayTray.exe" "--setup"
  done:
FunctionEnd

Section "Uninstall"
  ExecWait '$\"$INSTDIR\runtime\GatewayTray.exe$\" --uninstall'
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "PocketShellTray"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\PocketShellGateway"
  RMDir /r "$SMPROGRAMS\PocketShell Gateway"
  RMDir /r "$INSTDIR"
  ; Preserve owner-private keys, logs and existing sessions under PocketShellGateway.
SectionEnd
