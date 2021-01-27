@echo off

echo Starting build dnspx application...
cd ..
pyinstaller --name dnspx --console --onefile --icon logo.ico app.py

pause
exit
