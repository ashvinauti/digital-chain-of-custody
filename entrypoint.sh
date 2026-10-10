#!/bin/sh
set -e
# Creates tables + append-only triggers, then the first admin if none exists.
flask bootstrap-admin
# --preload: build the app (and run schema setup) once, before forking workers.
exec gunicorn --preload --workers 3 --bind 0.0.0.0:8000 wsgi:app
