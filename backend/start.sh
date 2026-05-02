#!/bin/bash
source ../venv/bin/activate
uvicorn main:app --reload --port 8000 --host 0.0.0.0
