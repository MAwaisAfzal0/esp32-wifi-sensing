@echo off
rem Dashboard for the ESP32 CSI presence detector.
rem   run_dashboard.bat                          simulated room, no board needed
rem   run_dashboard.bat --source serial          live from COM6 (asks for Wi-Fi creds)
rem   run_dashboard.bat --source sim --factor 4  replay the scenario 4x faster
cd /d D:\Development\esp32\sensing
D:\Development\esp32\.tools\venv\Scripts\python.exe -u tools\dashboard.py %*
