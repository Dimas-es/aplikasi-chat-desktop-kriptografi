; Script Inno Setup untuk Aplikasi CryptoChat
; Menghasilkan CryptoChat_Setup_v1.0.exe

#define MyAppName "CryptoChat"
#define MyAppVersion "1.0"
#define MyAppPublisher "Proyek Kriptografi Hybrid"
#define MyAppExeName "CryptoChat.exe"
#define MyRelayExeName "RelayServer.exe"

[Setup]
AppId={{9F82A34C-6A5B-4C23-8B39-D39F0B89C331}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
OutputDir=dist\Setup
OutputBaseFilename=CryptoChat_Setup_v1.0
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64

[Languages]
Name: "indonesian"; MessagesFile: "compiler:Languages\Indonesian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Seluruh berkas hasil build portabel
Source: "dist\CryptoChat_Portable\App\*"; DestDir: "{app}\App"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "dist\CryptoChat_Portable\Relay\*"; DestDir: "{app}\Relay"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "dist\CryptoChat_Portable\PETUNJUK_PENGGUNAAN.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\CryptoChat_Portable\*.bat"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\App\{#MyAppExeName}"
Name: "{group}\Relay Server LAN"; Filename: "{app}\Relay\{#MyRelayExeName}"
Name: "{group}\Petunjuk Penggunaan"; Filename: "{app}\PETUNJUK_PENGGUNAAN.txt"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\App\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\App\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
