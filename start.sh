#!/usr/bin/env sh

WRKRS=3
PORTN=7403
USERN=nobody

cd $(dirname $0)
source venv/bin/activate

gunicorn -b [::1]:$PORTN -b 127.0.0.1:$PORTN \
		-u $USERN -w $WRKRS checklame_rest:FLASK_APP

# eof
