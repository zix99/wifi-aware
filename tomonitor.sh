#!/bin/bash
/etc/init.d/network-manager stop
ifconfig wlp3s0 down
iwconfig wlp3s0 mode monitor
ifconfig wlp3s0 up
