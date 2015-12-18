#!/bin/bash
# Author : Nitin Chaudhary <nchaudha@usc.edu>

function KILL_PROCESSES {
	USERNAME=`whoami`
	PID=
	echo "Checking & Terminating zombie client & server processes for user: $USERNAME"
	PID=`ps -aux | grep $USERNAME | grep client | awk {'print $2'}`
	kill -15 $PID 2>/dev/null
	PID=`ps -aux | grep $USERNAME | grep server | awk {'print $2'}`
	kill -15 $PID 2>/dev/null
}

{
	KILL_PROCESSES
}


