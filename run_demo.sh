#!/bin/bash
source .venv/bin/activate
export VERITAS_DB_PATH="veritas_dev.db"
export JWT_SECRET_KEY="test_secret_for_running"

# Start backend using nohup so it survives the script exiting
nohup uvicorn backend.main:app --host 127.0.0.1 --port 8000 > backend.log 2>&1 &

# Start frontend using nohup
cd mobile
nohup python3 -m http.server 8080 > ../frontend.log 2>&1 &
