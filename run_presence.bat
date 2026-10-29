@echo off
rem Runs the CSI presence detector. Needs COM6 free and the board powered.
cd /d D:\Development\esp32\sensing
D:\Development\esp32\.tools\venv\Scripts\python.exe tools\csi_presence.py --port COM6 %*
