#!/bin/bash

cd /home/luisrt/apps/clasificador_ia || exit 1

source venv/bin/activate

uvicorn main:app --host 0.0.0.0 --port 6112
