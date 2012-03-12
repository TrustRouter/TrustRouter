[Files]
; copy the TrustRouter module incl. security sub-module
Source: "usermode\trustrouter\*"; DestDir: "{app}\python\Lib\site-packages\trustrouter"
Source: "usermode\trustrouter\security\*"; DestDir: "{app}\python\Lib\site-packages\trustrouter\security"; Flags: recursesubdirs
Source: "usermode\service.py"; DestDir: "{app}\bin"
Source: "usermode\winservice.py"; DestDir: "{app}\bin"

; copy the callout driver
Source: kernelmode\windows\bin\i386\trustrtr.inf; DestDir: {app}\driver
Source: kernelmode\windows\bin\i386\trustrtr.sys; DestDir: {app}\driver

; copy program to install windows filtering platform drivers
Source: "kernelmode\windows\installWFPFilter.exe"; DestDir: {app}\driver; Flags: deleteafterinstall

; copy Python32 installation directory and the .dlls needed by PyWin
Source: "packaging\Windows\Python32\*"; DestDir: {app}\python; Flags: recursesubdirs
Source: "packaging\Windows\pywinddls\*"; DestDir: {sys}

; the visual c++ runtime is needed by the security module
Source: "packaging\Windows\vcredist_x86.exe"; DestDir: {app}; Flags: deleteafterinstall

[Run]
Filename: {app}\vcredist_x86.exe; Parameters: /q /norestart; StatusMsg: "Installing Visual C++ Runtime..."

; without adding this rule, Certification Path Advertisments could be blcoked by Windows Firewall
Filename: {sys}\netsh.exe; Parameters: "advfirewall firewall add rule name=""Allow ICMP CPA Messages"" dir=in action=allow description=""Allows Certification Path Advertisments to enable TrustRouter the verification of Router Advertisments."" profile=any protocol=icmpv6:149,any"; StatusMsg: "Adding Firewall Rule for CPAs..."
Filename: {app}\driver\installWFPFilter.exe; StatusMsg: "Installing WFP filters..."

; start the TrustRouter service that uses windows.py
Filename: {app}\python\python.exe; Parameters: """{app}\bin\service.py"""

;Filename: {sys}\rundll32.exe; Parameters: setupapi,InstallHinfSection DefaultInstall 128 {app}\driver\trustrtr.inf; StatusMsg: "Installing Callout Driver..."; Flags: nowait

[Setup]
AppCopyright=BSD
AppName=TrustRouter
AppVerName=1.0.0
DefaultDirName={pf}\TrustRouter
;AlwaysRestart=yes

[Code]
{ After installation is finished, the driver is installed via the INF-file. 
  This must happen at the end because it prompts for restart and
  we don't want this to happen in the middle of the installation. }
procedure CurStepChanged(CurStep: TSetupStep);
var resultCode: Integer;
begin
  if CurStep=ssDone then begin
    Exec(ExpandConstant('{sys}\rundll32.exe'), ExpandConstant('setupapi,InstallHinfSection DefaultInstall 132 {app}\driver\trustrtr.inf'), '',  SW_SHOW, ewWaitUntilTerminated, resultCode)
  end;
end;

[InnoIDE_Settings]
UseRelativePaths=false
