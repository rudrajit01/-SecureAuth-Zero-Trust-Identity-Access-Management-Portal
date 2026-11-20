@echo off
echo Installing requirements...
pip install -r requirements.txt
echo.
echo Starting SecureAuth at http://127.0.0.1:5000
start "" http://127.0.0.1:5000
python app.py
pause
