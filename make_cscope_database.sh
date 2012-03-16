#!/bin/bash

CSCOPE_FILES="cscope.files"
find . -name "*.[ch]" -print > "${CSCOPE_FILES}"
cscope -b -q -k