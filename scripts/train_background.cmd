@echo off
rem Run CNN training as a Windows scheduled task, so it keeps running when the
rem SSH connection drops (Windows OpenSSH ends every process of a closed session).
rem
rem   scripts\train_background.cmd start --model cnn --device cuda
rem   scripts\train_background.cmd status        (task state + last log lines)
rem   scripts\train_background.cmd stop
rem   scripts\train_background.cmd show --model cnn   (only write + print the runner)
rem
rem Output is appended to logs\train.log. Training resumes from its last saved
rem epoch, so "start" with the same arguments after a stop continues the run.
setlocal
set "REPO=%~dp0.."
for %%I in ("%REPO%") do set "REPO=%%~fI"
set "TASK=PhishingDetectorTrain"
set "LOG=%REPO%\logs\train.log"
set "RUNNER=%REPO%\logs\run_train.cmd"

if /i "%~1"=="start" goto prepare
if /i "%~1"=="show" goto prepare
if /i "%~1"=="status" goto status
if /i "%~1"=="stop" goto stop
echo usage: %~nx0 start^|show [train_cnn arguments] ^| status ^| stop
exit /b 2

:prepare
set "ACTION=%~1"
shift
set "ARGS="
:collect
if "%~1"=="" goto write
set "ARGS=%ARGS% %1"
shift
goto collect

:write
if not exist "%REPO%\.venv\Scripts\python.exe" (
    echo ERROR: %REPO%\.venv not found. Create the virtual environment first.
    exit /b 1
)
if not exist "%REPO%\logs" mkdir "%REPO%\logs"
> "%RUNNER%" (
    echo @echo off
    echo cd /d "%REPO%"
    echo echo ===== %%date%% %%time%% start: train_cnn%ARGS% ^>^> "%LOG%"
    echo "%REPO%\.venv\Scripts\python.exe" -u -m src.training.train_cnn%ARGS% ^>^> "%LOG%" 2^>^&1
    echo echo ===== %%date%% %%time%% exit code %%errorlevel%% ^>^> "%LOG%"
)
if /i "%ACTION%"=="show" (
    type "%RUNNER%"
    exit /b 0
)

rem /NP: run whether or not you are logged on, no password stored, local resources only.
schtasks /create /tn "%TASK%" /tr "\"%RUNNER%\"" /sc once /st 00:00 /ru "%USERDOMAIN%\%USERNAME%" /np /rl limited /f >nul 2>&1
if errorlevel 1 (
    echo Note: could not create a background task without a password; using "only while
    echo you are logged on to this PC" instead.
    schtasks /create /tn "%TASK%" /tr "\"%RUNNER%\"" /sc once /st 00:00 /it /rl limited /f >nul
    if errorlevel 1 (
        echo ERROR: could not create the scheduled task.
        exit /b 1
    )
)
schtasks /run /tn "%TASK%" >nul
if errorlevel 1 (
    echo ERROR: could not start the scheduled task.
    exit /b 1
)
echo Training started in the background. You can now disconnect safely.
echo Check progress:  scripts\train_background.cmd status
echo Full log:        %LOG%
exit /b 0

:status
schtasks /query /tn "%TASK%" /fo list /v 2>nul | findstr /i /c:"Status:" /c:"Last Run Time" /c:"Last Result"
if errorlevel 1 echo No training task found.
if exist "%LOG%" (
    echo ---- last log lines ----
    powershell -NoProfile -Command "Get-Content -Tail 15 -LiteralPath $env:LOG"
)
exit /b 0

:stop
schtasks /end /tn "%TASK%"
echo Stopped. Progress up to the last finished epoch is saved; "start" resumes it.
exit /b 0
