title DirtCaps *CapsTempDelete by. Efe
@echo off
SET count=1
color 4
Echo DirtCaps by. Efe

:menu
cls
Echo ----------------------------------------------------
Echo.               ! !! DirtCaps !! !
Echo ----------------------------------------------------
Echo.     (  Windows 10 Temp,Prefetch PC Drop icin )
Echo ----------------------------------------------------
echo.
echo.       Yapmak istediginiz islemi Seciniz!
echo.
echo [1] Onbelllekleri Sil
Echo ----------------------------------------------------
echo [2] Cikis
echo.
set /p op="Numara: >>> "
if %op%==1 goto 1
if %op%==2 goto exit
goto error


:1
cls
Echo ----------------------------------------------------
echo.       Onbellek Temp Prefetch Temizleme
Echo ----------------------------------------------------
echo.
echo Lutfen Bekleyin....
ping localhost -n 3 >nul
del /q /f /s %temp%\*
del /s /q C:\Windows\temp\*
del /s /q C:\Users\%username%\AppData\Local\Temp\*
del /q /f /s %temp%\*.* /Q
del /s /q C:\Windows\temp\*.* /Q
del /s /q C:\Users\%username%\AppData\Local\Temp\*.* /Q
cd C:\Users\%username%\AppData\Local
rmdir /S /Q Temp
del C:\Windows\Prefetch\*.* /Q
del C:\Windows\Temp\*.* /Q
del C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Recent Items*.* /Q
cls
Echo ----------------------------------------------------
echo.                islem Tamamlanmistir.
echo.                                     DirtCaps by Efe
Echo ----------------------------------------------------
pause
goto menu


:error
cls
echo Bilinmeyen Komut Arasinda Secim Yap 1-2.
ping localhost -n 3 >nul
goto menu
:exit