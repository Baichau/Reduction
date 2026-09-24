#define MyAppName "Local Redaction"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "Local Redaction"
#define MyAppExeName "SecureRedactionHost.exe"

[Setup]
AppId={{B1C4DF0C-CA72-4F46-B5EA-123456789001}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\LocalRedaction
DefaultGroupName={#MyAppName}
OutputDir=..\dist\installer
OutputBaseFilename=LocalRedactionSetup
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
WizardStyle=modern
UninstallDisplayIcon={app}\{#MyAppExeName}

[Files]
Source: "..\dist\host\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\dist\worker\LocalRedactionWorker\*"; DestDir: "{app}\worker"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\dist\worker\LocalRedactionParser\*"; DestDir: "{app}\worker"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\frontend\dist\*"; DestDir: "{app}\frontend"; Flags: ignoreversion recursesubdirs createallsubdirs

[Dirs]
Name: "{app}\backend\data"

[Icons]
Name: "{autodesktop}\Local Redaction"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Local Redaction"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall Local Redaction"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Local Redaction"; Flags: postinstall nowait skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}\frontend"
Type: filesandordirs; Name: "{app}\worker"
Type: filesandordirs; Name: "{app}\backend"

[Code]
function InitializeSetup(): Boolean;
begin
  MsgBox('This is a local pilot build. It is not a certified production security release.', mbInformation, MB_OK);
  Result := True;
end;
