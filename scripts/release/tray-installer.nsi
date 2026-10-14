Unicode true
!include "LogicLib.nsh"
!include "x64.nsh"
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
  ; Install the identical standalone PSC payload under its versioned per-user prefix.
  ; Explicit 64-bit inbox PowerShell; no profile and no downloads at install time.
  StrCpy $1 "$SYSDIR\WindowsPowerShell\v1.0\powershell.exe"
  ${If} ${RunningX64}
    StrCpy $1 "$WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
  ${EndIf}
  nsExec::ExecToStack '$\"$1$\" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $\"$INSTDIR\psc-package\install.ps1$\" -SshPath $\"$INSTDIR\psc-ssh\ssh.exe$\" -InstallVariant gateway-ssh10'
  Pop $2
  Pop $3
  FileOpen $4 "$INSTDIR\psc-install.log" w
  FileWrite $4 "$3"
  FileClose $4
  StrCmp $2 0 psc_continue
  MessageBox MB_ICONEXCLAMATION "PSC installation failed. Gateway installation will continue. Check $INSTDIR\psc-install.log for details. Exit code: $2" /SD IDOK
  psc_continue:
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  ReadEnvStr $0 "APPDATA"
  StrCmp $0 "" 0 +2
  StrCpy $0 "$APPDATA"
  CreateDirectory "$0\Microsoft\Windows\Start Menu\Programs\PocketShell Gateway"
  CreateShortcut "$0\Microsoft\Windows\Start Menu\Programs\PocketShell Gateway\PocketShell Gateway.lnk" "$INSTDIR\runtime\GatewayTray.exe"
  CreateShortcut "$0\Microsoft\Windows\Start Menu\Programs\PocketShell Gateway\Gateway Setup.lnk" "$INSTDIR\runtime\GatewayTray.exe" "--setup"
  StrCmp $2 0 psc_shortcut
  Delete "$0\Microsoft\Windows\Start Menu\Programs\PocketShell Gateway\PSC Terminal.lnk"
  Goto psc_shortcut_done
  psc_shortcut:
  CreateShortcut "$0\Microsoft\Windows\Start Menu\Programs\PocketShell Gateway\PSC Terminal.lnk" "$WINDIR\System32\cmd.exe" '/K $\"$LOCALAPPDATA\PocketShell\psc\bin\psc.cmd$\" --help'
  psc_shortcut_done:
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
  ; PSC is independently versioned; retain its install and user PATH shim.
SectionEnd
