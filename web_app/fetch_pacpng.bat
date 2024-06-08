@echo off
set "PI_USER=taha"
set "PI_HOST=192.168.1.15"
set "PI_PATH=/home/taha/Packets/"
set "LOCAL_PATH=C:\Users\taha\OneDrive\Desktop\FYP_SWITCH\Packets\Pi_packets"
set "PYTHON_SCRIPT=C:\Users\taha\OneDrive\Desktop\FYP_SWITCH\nids\web_app\Anomaly.py"

:: Retrieve the latest pcapng file
echo Attempting to download pcapng files from Raspberry Pi...
scp %PI_USER%@%PI_HOST%:%PI_PATH%*.pcapng %LOCAL_PATH%
if %ERRORLEVEL% equ 0 (
    echo SCP operation successful.
) else (
    echo SCP operation failed. Error Level: %ERRORLEVEL%
    goto EndScript
)

:: Initialize variable to store the latest pcap file
set "LATEST_PCAP="

:: Find the latest downloaded pcapng file
for /r "%LOCAL_PATH%" %%a in (*.pcapng) do (
    set "LATEST_PCAP=%%a"
)

:: Check if a pcap file was found and run the Python script on it
if defined LATEST_PCAP (
    echo Running Python script on the latest pcap file: "%LATEST_PCAP%"
    python "%PYTHON_SCRIPT%" "%LATEST_PCAP%"
    if %ERRORLEVEL% equ 0 (
        echo Python script executed successfully.
    ) else (
        echo Python script execution failed. Error Level: %ERRORLEVEL%
    )
) else (
    echo No pcapng files found to process.
)

:EndScript
pause
