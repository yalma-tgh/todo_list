#!/bin/bash
echo "Starting FastAPI in debug auth mode..."
DEBUG_AUTH_MODE=true uvicorn main:app --host 0.0.0.0 --port 8000 --reload 