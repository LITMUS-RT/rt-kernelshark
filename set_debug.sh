#!/bin/bash
PATTERN="(define debug[a-z_]+\s*)[-0-9]+"
sed -ri "s/$PATTERN/\\1$1/gi" *.[ch]
grep -HirE "$PATTERN" *.[ch]