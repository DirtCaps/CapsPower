@Echo off
title DirtCaps FPS Boost Mode
color 4
REM Made DirtCaps by. Efe


REM Windows 10 DirtCaps FPS Boost Mode:


Echo. ; ----------------------------------------
Echo. ;            ! !! DirtCaps !! !
Echo. ; ----------------------------------------
Echo. ;       (  DirtCapsFPS Boost Mode! )

REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v AutoReboot /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\MemoryManager" /v DxgMms2OfferReclaim /t REG_DWORD /d 2 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v UseSelfRefreshVRAMInS3 /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler /v VsyncIdleTimeout /t REG_DWORD /d 0 /f
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskCleanup\SilentCleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\Defrag\ScheduledDefrag" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
schtasks /Change /TN "Microsoft\Windows\Location\Notifications" /Disable
schtasks /Change /TN "Microsoft\Windows\Location\WindowsActionDialog" /Disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /Disable
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
schtasks /Change /TN "Microsoft\Windows\Offline Files\Background Synchronization" /Disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable
schtasks /Change /TN "Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\IndexerAutomaticMaintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Media Sharing\UpdateLibrary" /Disable
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AITEventLog" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AppModel" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AppPlat" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Audio" /v "Start" /t REG_DWORD /d 0 /f
@echo Import DirtCaps FPS Boost Mode
powercfg -delete 33333333-3333-3333-3333-333333333333
powercfg -import "C:\CapsPower\DirtCapsFPSModev2.pow" 33333333-3333-3333-3333-333333333333
powercfg -delete 22222222-2222-2222-2222-222222222222
powercfg -import "C:\CapsPower\DirtCapsFPSMode.pow" 22222222-2222-2222-2222-222222222222
Powercfg -changename 22222222-2222-2222-2222-222222222222 "Yuksek Performans v1" "DirtCaps by. Efe"
@powercfg -SETACTIVE "33333333-3333-3333-3333-333333333333"
Powercfg -changename 33333333-3333-3333-3333-333333333333 "Yuksek Performans v2" "DirtCaps by. Efe"
powercfg -import "C:\CapsPower\DirtCapsFPSModev3.pow" 44444444-4444-4444-4444-444444444444
powercfg -SETACTIVE "44444444-4444-4444-4444-444444444444"
Powercfg -changename 44444444-4444-4444-4444-444444444444 "Yuksek Performans Oyun" "DirtCaps by. Efe"
@echo Delete Balanced
powercfg -delete 381b4222-f694-41f0-9685-ff5bb260df2e
@echo Delete Power saver
powercfg -delete a1841308-3541-4fab-bc81-f71556f20b4a
powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\Powerschemes\44444444-4444-4444-4444-444444444444\0012ee47-9041-4b5d-9b77-535fba8b1442\6738e2c4-e8a5-4a42-b16a-e040e769756e" /v "AcSettingIndex" /t reg_dword /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\Powerschemes\44444444-4444-4444-4444-444444444444\238c9fa8-0aad-41ed-83f4-97be242c8f20\94ac6d29-73ce-41a6-809f-6363ba21b47e" /v "AcSettingIndex" /t reg_dword /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\Powerschemes\44444444-4444-4444-4444-444444444444\238c9fa8-0aad-41ed-83f4-97be242c8f20\bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d" /v "AcSettingIndex" /t reg_dword /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\Powerschemes\44444444-4444-4444-4444-444444444444\245d8541-3943-4422-b025-13a784f679b7" /v "AcSettingIndex" /t reg_dword /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\Powerschemes\44444444-4444-4444-4444-444444444444\2a737441-1930-4402-8d77-b2bebba308a3\0853a681-27c8-4100-a2fd-82013e970683" /v "AcSettingIndex" /t reg_dword /d "100000" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\Powerschemes\44444444-4444-4444-4444-444444444444\2a737441-1930-4402-8d77-b2bebba308a3\48e6b7a6-50f5-4782-a5d4-53bb8f07e226" /v "AcSettingIndex" /t reg_dword /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\Powerschemes\44444444-4444-4444-4444-444444444444\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009" /v "AcSettingIndex" /t reg_dword /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\Powerschemes\44444444-4444-4444-4444-444444444444\4f971e89-eebd-4455-a8de-9e59040e7347\96996bc0-ad50-47ec-923b-6f41874dd9eb" /v "AcSettingIndex" /t reg_dword /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\Powerschemes\44444444-4444-4444-4444-444444444444\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "AcSettingIndex" /t reg_dword /d "100" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\Powerschemes\44444444-4444-4444-4444-444444444444\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb" /v "AcSettingIndex" /t reg_dword /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\Powerschemes\44444444-4444-4444-4444-444444444444\54533251-82be-4824-96c1-47b60b740d00\5d76a2ca-e8c0-402f-a133-2158492d58ad" /v "AcSettingIndex" /t reg_dword /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\Powerschemes\44444444-4444-4444-4444-444444444444\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c" /v "AcSettingIndex" /t reg_dword /d "100" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\Powerschemes\44444444-4444-4444-4444-444444444444\54533251-82be-4824-96c1-47b60b740d00\bc5038f7-23e0-4960-96da-33abaf5935ec" /v "AcSettingIndex" /t reg_dword /d "100" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\Powerschemes\44444444-4444-4444-4444-444444444444\7516b95f-f776-4464-8c53-06167f40cc99\3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e" /v "AcSettingIndex" /t reg_dword /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\Powerschemes\44444444-4444-4444-4444-444444444444\7516b95f-f776-4464-8c53-06167f40cc99\aded5e82-b909-4619-9949-f5d71dac0bcb" /v "AcSettingIndex" /t reg_dword /d "100" /f
Powercfg -SetACValueIndex 44444444-4444-4444-4444-444444444444 fea3413e-7e05-4911-9a71-700331f1c294 0e796bdb-100d-47d6-a2d5-f7d2daa51f51 0
Powercfg -SetDCValueIndex 44444444-4444-4444-4444-444444444444 fea3413e-7e05-4911-9a71-700331f1c294 0e796bdb-100d-47d6-a2d5-f7d2daa51f51 0
Powercfg -SetACValueIndex 44444444-4444-4444-4444-444444444444 fea3413e-7e05-4911-9a71-700331f1c294 245d8541-3943-4422-b025-13a784f679b7 1
Powercfg -SetDCValueIndex 44444444-4444-4444-4444-444444444444 fea3413e-7e05-4911-9a71-700331f1c294 245d8541-3943-4422-b025-13a784f679b7 1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{025A5937-A6BE-4686-A844-36FE4BEC8B6D}" /v PreferredPlan /t REG_SZ /d 44444444-4444-4444-4444-444444444444 /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{025A5937-A6BE-4686-A844-36FE4BEC8B6D}" /v PreferredPlan /t REG_SZ /d 44444444-4444-4444-4444-444444444444 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Controls Folder\PowerCfg" /v PreferredPlan /t REG_SZ /d 44444444-4444-4444-4444-444444444444 /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Controls Folder\PowerCfg" /v PreferredPlan /t REG_SZ /d 44444444-4444-4444-4444-444444444444 /f
powercfg -devicedisablewake "HID-compliant mouse"
powercfg -devicedisablewake "HID keyboard Device"
bcdedit /deletevalue useplatformclock
bcdedit /set bootmenupolicy standard
bcdedit /set bootux disabled
bcdedit /set hypervisorlaunchtype off
bcdedit /set nx optout
bcdedit /set quietboot yes
bcdedit /set tpmbootentropy forcedisable
bcdedit /set {globalsettings} custom:16000067 true
bcdedit /set {globalsettings} custom:16000068 true
bcdedit /set {globalsettings} custom:16000069 true
powercfg -change -monitor-timeout-ac 0
powercfg -change -monitor-timeout-dc 0
powercfg -change -standby-timeout-ac 0
powercfg -change -standby-timeout-dc 0
powercfg -change -disk-timeout-ac 0
powercfg -change -disk-timeout-dc 0
powercfg -change -hibernate-timeout-ac 0
powercfg -change -hibernate-timeout-dc 0
powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
powercfg /X monitor-timeout-ac 0
powercfg /X monitor-timeout-dc 0
powercfg /X standby-timeout-ac 0
powercfg /X standby-timeout-dc 0
powercfg /X -disk-timeout-ac 0
powercfg /X -disk-timeout-dc 0
powercfg /X -hibernate-timeout-ac 0
powercfg /X -hibernate-timeout-dc 0
powercfg /setACvalueindex scheme_current SUB_PROCESSOR PERFBOOSTMODE 2
powercfg /setDCvalueindex scheme_current SUB_PROCESSOR PERFBOOSTMODE 2
powercfg /setACvalueindex scheme_current SUB_PROCESSOR SCHEDPOLICY 3
powercfg /setDCvalueindex scheme_current SUB_PROCESSOR SCHEDPOLICY 5
powercfg /setACvalueindex scheme_current SUB_INTSTEER MODE 5
powercfg /setDCvalueindex scheme_current SUB_INTSTEER MODE 5
powercfg /setACvalueindex scheme_current SUB_PROCESSOR SHORTSCHEDPOLICY 3
powercfg /setDCvalueindex scheme_current SUB_PROCESSOR SHORTSCHEDPOLICY 5
powercfg /setACvalueindex scheme_current SUB_PROCESSOR SCHEDPOLICY 3
powercfg /setDCvalueindex scheme_current SUB_PROCESSOR SCHEDPOLICY 5
powercfg /setACvalueindex scheme_current SUB_PROCESSOR SHORTSCHEDPOLICY 2
powercfg /setDCvalueindex scheme_current SUB_PROCESSOR SHORTSCHEDPOLICY 2
powercfg /setACvalueindex scheme_current SUB_PROCESSOR SCHEDPOLICY 2
powercfg /setDCvalueindex scheme_current SUB_PROCESSOR SCHEDPOLICY 2
powercfg /setACvalueindex scheme_current SUB_INTSTEER MODE 6
powercfg /setDCvalueindex scheme_current SUB_INTSTEER MODE 6
powercfg /setACvalueindex scheme_current SUB_PROCESSOR PERFBOOSTMODE 2
powercfg /setDCvalueindex scheme_current SUB_PROCESSOR PERFBOOSTMODE 2
powercfg /setACvalueindex scheme_current SUB_PCIEXPRESS ASPM 0
powercfg /OverlaySetActive OVERLAY_SCHEME_NONE
powercfg /setacvalueindex SCHEME_BALANCED SUB_PROCESSOR PROCTHROTTLEMAX 100
powercfg /setdcvalueindex SCHEME_BALANCED SUB_PROCESSOR PROCTHROTTLEMAX 100
powercfg -setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100
powercfg -setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100
powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100
powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100
powercfg /setacvalueindex scheme_current sub_processor 0cc5b647-c1df-4637-891a-dec35c318583 100
powercfg /setacvalueindex scheme_current sub_processor ea062031-0e34-4ff1-9b6d-eb1059334028 100
powercfg /setdcvalueindex scheme_current sub_processor 0cc5b647-c1df-4637-891a-dec35c318583 100
powercfg /setdcvalueindex scheme_current sub_processor ea062031-0e34-4ff1-9b6d-eb1059334028 100
PowerCfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR IDLEDISABLE 000
PowerCfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR IDLEDISABLE 000
powercfg /setACvalueindex scheme_current SUB_GRAPHICS GPUPREFERENCEPOLICY 1
powercfg /setDCvalueindex scheme_current SUB_GRAPHICS GPUPREFERENCEPOLICY 1
powercfg /setACvalueindex scheme_current SUB_PROCESSOR CPPERF 2
powercfg /setDCvalueindex scheme_current SUB_PROCESSOR CPPERF 2
powercfg /setACvalueindex scheme_current SUB_PROCESSOR CPPERF1 2
powercfg /setDCvalueindex scheme_current SUB_PROCESSOR CPPERF1 2
powercfg /setACvalueindex scheme_current SUB_PROCESSOR SYSCOOLPOL 1
powercfg /setDCvalueindex scheme_current SUB_PROCESSOR SYSCOOLPOL 1
Powercfg /setACvalueindex scheme_balanced SUB_SLEEP RTCWAKE 1
Powercfg /setACvalueindex scheme_current SUB_SLEEP RTCWAKE 1
powercfg /setACvalueindex scheme_current SUB_PROCESSOR CPMINCORES 100
powercfg /setDCvalueindex scheme_current SUB_PROCESSOR CPMINCORES 100
powercfg /setACvalueindex scheme_current SUB_PROCESSOR CPMINCORES1 100
powercfg /setDCvalueindex scheme_current SUB_PROCESSOR CPMINCORES1 100
Powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 100
Powercfg -setacvalueindex scheme_current sub_processor CPMINCORES1 100
Powercfg -setacvalueindex scheme_current sub_processor CPMAXCORES 100
Powercfg -setacvalueindex scheme_current sub_processor CPMAXCORES1 100
PowerCfg /SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR IDLEDISABLE 000
PowerCfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR IDLEDISABLE 000
powercfg setacvalueindex SCHEME_BALANCED SUB_VIDEO VIDEOIDLE 0
powercfg setdcvalueindex SCHEME_BALANCED SUB_VIDEO VIDEOIDLE 0
powercfg setdcvalueindex SCHEME_MIN SUB_VIDEO VIDEOIDLE 0
powercfg setacvalueindex SCHEME_MIN SUB_VIDEO VIDEOIDLE 0
powercfg setdcvalueindex SCHEME_MAX SUB_VIDEO VIDEOIDLE 0
powercfg setacvalueindex SCHEME_MAX SUB_VIDEO VIDEOIDLE 0
powercfg /setdcvalueindex SCHEME_CURRENT SUB_SLEEP HYBRIDSLEEP Off
powercfg /setacvalueindex SCHEME_CURRENT SUB_SLEEP HYBRIDSLEEP Off
powercfg /setACvalueindex scheme_current SUB_VIDEO VIDEOCONLOCK 0
powercfg /setDCvalueindex scheme_current SUB_VIDEO VIDEOCONLOCK 0
powercfg /setACvalueindex scheme_current SUB_SLEEP REMOTEFILESLEEP 0
powercfg /setDCvalueindex scheme_current SUB_SLEEP REMOTEFILESLEEP 0
powercfg /setACvalueindex scheme_current SUB_PROCESSOR PERFDECTIME 2
powercfg /setDCvalueindex scheme_current SUB_PROCESSOR PERFDECTIME 2
powercfg /setACvalueindex scheme_current SUB_SLEEP REMOTEFILESLEEP 0
powercfg /setACvalueindex scheme_current SUB_SLEEP ALLOWSTANDBY 0
powercfg /setACvalueindex scheme_current SUB_SLEEP HIBERNATEIDLE 0
powercfg /setACvalueindex scheme_current SUB_SLEEP STANDBYIDLE 0
powercfg /setACvalueindex scheme_current SUB_SLEEP HYBRIDSLEEP 0
powercfg setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 0
powercfg setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 0
powercfg -H OFF
powercfg h off
powercfg -h off
powercfg /h off
powercfg.exe /hibernate off
powercfg -hibernate off
powercfg -H Off
powercfg /H Off
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583 /v ValueMax /t REG_DWORD /d 100 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583 /v ValueMin /t REG_DWORD /d 100 /f
Reg add HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\93b8b6dc-0698-4d1c-9ee4-0644e900c85d\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c /f /t reg_dword /v AcSettingIndex /d 2
Reg add HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\bae08b81-2d5e-4688-ad6a-13243356654b\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c /f /t reg_dword /v AcSettingIndex /d 2
Reg add HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\93b8b6dc-0698-4d1c-9ee4-0644e900c85d\DefaultPowerSchemeValues\33333333-3333-3333-3333-333333333333 /f /t reg_dword /v AcSettingIndex /d 2
Reg add HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\bae08b81-2d5e-4688-ad6a-13243356654b\DefaultPowerSchemeValues\33333333-3333-3333-3333-333333333333 /f /t reg_dword /v AcSettingIndex /d 2
Reg add HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\93b8b6dc-0698-4d1c-9ee4-0644e900c85d\DefaultPowerSchemeValues\44444444-4444-4444-4444-444444444444 /f /t reg_dword /v AcSettingIndex /d 2
Reg add HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\bae08b81-2d5e-4688-ad6a-13243356654b\DefaultPowerSchemeValues\44444444-4444-4444-4444-444444444444 /f /t reg_dword /v AcSettingIndex /d 2
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power\PowerThrottling" /v PowerThrottlingOff /t REG_DWORD /d 1 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v AutoReboot /t REG_DWORD /d 0 /f
Reg.exe add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power /v CoreParkingDisabled /t REG_DWORD /d 0 /f
Reg.exe add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power /v AwayModeEnabled /t REG_DWORD /d 0 /f
Reg.exe add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power /v Class1InitialUnparkCount /t REG_DWORD /d 100 /f
Reg.exe add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power /v CsEnabled /t REG_DWORD /d 0 /f
Reg.exe add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power /v CustomizeDuringSetup /t REG_DWORD /d 1 /f
Reg.exe add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power /v EnergyEstimationEnabled /t REG_DWORD /d 1 /f
Reg.exe add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power /v HiberFileSizePercent /t REG_DWORD /d 0 /f
Reg.exe add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power /v HibernateEnabled /t REG_DWORD /d 0 /f
Reg.exe add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power /v MfBufferingThreshold /t REG_DWORD /d 0 /f
Reg.exe add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power /v PerfCalculateActualUtilization /t REG_DWORD /d 1 /f
Reg.exe add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power /v TimerRebaseThresholdOnDripsExit /t REG_DWORD /d 30 /f
Reg.exe add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power /v EventProcessorEnabled /t REG_DWORD /d 1 /f
Reg.exe add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power /v HiberFileType /t REG_DWORD /d 0 /f
Reg.exe add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power /v Class2InitialUnparkCount /t REG_DWORD /d 100 /f
Reg.exe add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power /v EnergyEstimationDisabled /t REG_DWORD /d 1 /f
Reg.exe add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power /v PerfBoostAtGuaranteed /t REG_DWORD /d 1 /f
Reg.exe add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power /v PpmMfBufferingThreshold /t REG_DWORD /d 0 /f
Reg.exe add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power /v MfOverridesDisabled /t REG_DWORD /d 1 /f
Reg.exe add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power /v PpmMfOverridesDisabled /t REG_DWORD /d 1 /f
Reg.exe add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power /v UserBatteryDischargeEstimator /t REG_DWORD /d 1 /f
Reg.exe add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power /v PowerThrottlingOff /t REG_DWORD /d 1 /f
Reg.exe add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling /v PowerThrottlingOff /t REG_DWORD /d 1 /f
powercfg.cpl
exit