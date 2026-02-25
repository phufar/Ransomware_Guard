source ./backend/.venv/bin/activate
sudo python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
deactivate
