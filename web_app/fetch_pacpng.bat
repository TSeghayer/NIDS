@echo off
set "PI_USER=taha"
set "PI_HOST=192.168.1.15"
set "PI_PATH=/home/taha/Packets/"
set "LOCAL_PATH=C:\Users\taha\OneDrive\Desktop\FYP_SWITCH\Packets\Pi_packets"
set "PYTHON_SCRIPT=C:\Users\taha\OneDrive\Desktop\FYP_SWITCH\Scripting\Anomaly.py"

:: Retrieve the latest pcapng file
scp %PI_USER%@%PI_HOST%:%PI_PATH%*.pcapng %LOCAL_PATH%

:: Run the Python script on the downloaded pcapng file
for /r %LOCAL_PATH% %%a in (*.pcapng) do (
    set "LATEST_PCAP=%%a"
)

python %PYTHON_SCRIPT% "%LATEST_PCAP%"

pause 
