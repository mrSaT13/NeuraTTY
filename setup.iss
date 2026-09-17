[Setup]
AppName=NeuraTTY
AppVersion=1.8
DefaultDirName={autopf}\NeuraTTY
DefaultGroupName=NeuraTTY
OutputBaseFilename=NeuraTTY_Installer_v1.8
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=lowest
SetupIconFile=resources\icon.ico
UninstallDisplayIcon={app}\NeuraTTY.exe
WizardStyle=modern
; Страницы выбора папки установки и группы меню Пуск — показываем явно
DisableDirPage=no
DisableProgramGroupPage=no
; Диалог выбора языка при старте (русский/английский)
ShowLanguageDialog=yes

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
russian.AdditionalIcons=Дополнительно:
russian.CreateDesktopIcon=Создать ярлык на рабочем столе
russian.RunApp=Запустить NeuraTTY
english.AdditionalIcons=Additional icons:
english.CreateDesktopIcon=Create a desktop icon
english.RunApp=Launch NeuraTTY

[Files]
Source: "dist\NeuraTTY.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "resources\*"; DestDir: "{app}\resources"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\NeuraTTY"; Filename: "{app}\NeuraTTY.exe"
Name: "{autodesktop}\NeuraTTY"; Filename: "{app}\NeuraTTY.exe"; Tasks: desktopicon

[Tasks]
Name: desktopicon; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Run]
Filename: "{app}\NeuraTTY.exe"; Description: "{cm:RunApp}"; Flags: nowait postinstall skipifsilent
