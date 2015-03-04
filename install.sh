#!/bin/bash

DST='/Applications/IDA Pro 6.6/idaq.app/Contents/MacOS/plugins/idarest.py'
SRC=idarest.py

cp $SRC "$DST"
chmod +x "$DST"
