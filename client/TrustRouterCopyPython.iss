[Files]
Source: "usermode\trustrouter\*"; DestDir: "{app}\python\Lib\site-packages\trustrouter"
Source: "usermode\trustrouter\security\*"; DestDir: "{app}\python\Lib\site-packages\trustrouter\security"; Flags: recursesubdirs
Source: "usermode\service.py"; DestDir: "{app}\bin"
Source: "usermode\winservice.py"; DestDir: "{app}\bin"

Source: kernelmode\windows\bin\i386\trustrtr.inf; DestDir: {app}\driver
Source: kernelmode\windows\bin\i386\trustrtr.sys; DestDir: {app}\driver

Source: "kernelmode\windows\installWFPFilter.exe"; DestDir: {app}\driver; Flags: deleteafterinstall

Source: "packaging\Windows\Python32\*"; DestDir: {app}\python; Flags: recursesubdirs
Source: "packaging\Windows\pywinddls\*"; DestDir: {sys}

Source: "packaging\Windows\vcredist_x86.exe"; DestDir: {app}; Flags: deleteafterinstall

[Run]
Filename: {app}\vcredist_x86.exe; Parameters: /q /norestart; StatusMsg: "Installing Visual C++ Runtime..."
Filename: {sys}\netsh.exe; Parameters: "advfirewall firewall add rule name=""Allow ICMP CPA Messages"" dir=in action=allow description=""Allows Certification Path Advertisments to enable TrustRouter the verification of Router Advertisments."" profile=any protocol=icmpv6:149,any"; StatusMsg: "Adding Firewall Rule for CPAs..."
Filename: {app}\driver\installWFPFilter.exe; StatusMsg: "Installing WFP filters..."

Filename: {app}\python\python.exe; Parameters: """{app}\bin\service.py"""

;Filename: {sys}\rundll32.exe; Parameters: setupapi,InstallHinfSection DefaultInstall 128 {app}\driver\trustrtr.inf; StatusMsg: "Installing Callout Driver..."; Flags: nowait

[Setup]
AppCopyright=BSD
AppName=TrustRouter
AppVerName=1.0.0
DefaultDirName={pf}\TrustRouter
;AlwaysRestart=yes

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
var resultCode: Integer;
begin
  if CurStep=ssDone then begin
    Exec(ExpandConstant('{sys}\rundll32.exe'), ExpandConstant('setupapi,InstallHinfSection DefaultInstall 128 {app}\driver\trustrtr.inf'), '',  SW_SHOW, ewWaitUntilTerminated, resultCode)
  end;
end;

procedure PythonPath();
var regVal, pathToPywinSetup:String; resultCode: Integer;
begin
  regVal := 'None';
  RegQueryStringValue(HKCR, 'Python.File\shell\open\command', '', regVal);
  Delete(regVal, Pos('"', regVal), 1);
  Delete(regVal, Pos('"', regVal), Length(regVal));
  pathToPywinSetup := ExpandConstant('{app}\pywin32\setup.py');
  MsgBox(pathToPywinSetup, mbInformation, MB_OK);
  Exec(regVal, '"' + pathToPywinSetup + '" install', '',  SW_SHOW, ewWaitUntilTerminated, resultCode)
end;

[InnoIDE_Settings]
UseRelativePaths=false
