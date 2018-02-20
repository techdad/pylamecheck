#!/usr/bin/env sh

source venv/bin/activate

_WRKS="3"
_PORT="7403"

gunicorn -b "[::1]:$_PORT" -b "127.0.0.1:$_PORT" \
		-w $_WRKS -D checklame_rest:FLASK_APP

# eof
