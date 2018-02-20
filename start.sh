#!/usr/bin/env sh

source venv/bin/activate

WRKS=3
PORT=7403

gunicorn -b [::1]:$PORT -b 127.0.0.1:$PORT \
		-w $WRKS checklame_rest:FLASK_APP

# eof
