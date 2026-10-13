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
  SetRegView 64
  SetOutPath "$INSTDIR"
  File /r "${PAYLOAD}\*.*"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  ReadEnvStr $0 "APPDATA"
  StrCmp $0 "" 0 +2
  StrCpy $0 "$APPDATA"
  CreateDirectory "$0\Microsoft\Windows\Start Menu\Programs\PocketShell Gateway"
  CreateShortcut "$0\Microsoft\Windows\Start Menu\Programs\PocketShell Gateway\PocketShell Gateway.lnk" "$INSTDIR\runtime\GatewayTray.exe"
  CreateShortcut "$0\Microsoft\Windows\Start Menu\Programs\PocketShell Gateway\Gateway Setup.lnk" "$INSTDIR\runtime\GatewayTray.exe" "--setup"
  CreateShortcut "$0\Microsoft\Windows\Start Menu\Programs\PocketShell Gateway\Uninstall.lnk" "$INSTDIR\Uninstall.exe"
  ClearErrors
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "PocketShellTray" '$\"$INSTDIR\runtime\GatewayTray.exe$\"'
  IfErrors startup_folder startup_done
  startup_folder:
  CreateDirectory "$0\Microsoft\Windows\Start Menu\Programs\Startup"
  CreateShortcut "$0\Microsoft\Windows\Start Menu\Programs\Startup\PocketShell Gateway.lnk" "$INSTDIR\runtime\GatewayTray.exe"
  IfErrors 0 startup_done
  SetErrorLevel 1
  startup_done:
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
  SetRegView 64
  ExecWait '$\"$INSTDIR\runtime\GatewayTray.exe$\" --uninstall'
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "PocketShellTray"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\PocketShellGateway"
  ReadEnvStr $0 "APPDATA"
  StrCmp $0 "" 0 +2
  StrCpy $0 "$APPDATA"
  Delete "$0\Microsoft\Windows\Start Menu\Programs\Startup\PocketShell Gateway.lnk"
  RMDir /r "$0\Microsoft\Windows\Start Menu\Programs\PocketShell Gateway"
  RMDir /r "$INSTDIR"
  ; Preserve owner-private keys, logs and existing sessions under PocketShellGateway.
SectionEnd
