#!/bin/sh
/bin/ftpclient -n <<!
open $1 $7
user $2 $3
binary
cd $4
lcd $5
get $6
close
bye
!
