@echo off

echo Starting build dnspx application...

cd ..

::nuitka --standalone --onefile --show-memory --remove-output --show-progress --verbose --output-filename=dnspx.exe --windows-icon-from-ico=logo.ico app.py
nuitka --standalone --show-memory --remove-output --show-progress --verbose --output-filename=dnspx.exe --windows-icon-from-ico=logo.ico app.py

pause
exit
