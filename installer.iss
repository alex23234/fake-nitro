[Setup]
AppName=fakenitro
AppVersion=1.0
DefaultDirName={autopf}\fakenitro
DefaultGroupName=fakenitro
OutputBaseFilename=fakenitro-installer

[Files]
; change the exe location to whatever it is on your device
Source: "C:\Users\{username}\code\dist\main.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\fakenitro"; Filename: "{app}\main.exe"
Name: "{commonstartup}\fakenitro"; Filename: "{app}\main.exe"
