[Setup]
AppName=NeuraTTY
AppVersion=1.7
DefaultDirName={autopf}\NeuraTTY
DefaultGroupName=NeuraTTY
OutputBaseFilename=NeuraTTY_Installer_v1.7
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=lowest
SetupIconFile=resources\icon.ico
UninstallDisplayIcon={app}\NeuraTTY.exe

[Files]
Source: "dist\NeuraTTY.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "resources\*"; DestDir: "{app}\resources"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\NeuraTTY"; Filename: "{app}\NeuraTTY.exe"
Name: "{autodesktop}\NeuraTTY"; Filename: "{app}\NeuraTTY.exe"; Tasks: desktopicon

[Tasks]
Name: desktopicon; Description: "Создать ярлык на рабочем столе"; GroupDescription: "Дополнительно:"; Flags: unchecked

[Run]
Filename: "{app}\NeuraTTY.exe"; Description: "Запустить NeuraTTY"; Flags: nowait postinstall skipifsilent
