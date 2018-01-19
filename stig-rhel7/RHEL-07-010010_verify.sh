#!/bin/bash
#
# Author: paul.c.arnold4.ctr@mail.mil
#
# Some improperly SPEC'd RPMs (e.g. not RedHat-official RPMs) generate
# false positives on this check.  The DISA official check also shows files
# which are less permissive than default, but it is not obvious from the
# default result output.
#
#
## DISA Stuff ##
#
# STIG Release: Red Hat Enterprise Linux 7 Security Technical Implementation
#               Guide - Version 1 - Release 3
#
# Rule Title:   The file permissions, ownership, and group membership of 
#               system files and commands must match the vendor values. 
#
# STIG ID:      RHEL-07-010010
# Rule ID:      SV-86473r2_rule
# Vuln ID:      V-71849
# Severity:     CAT I

echo -e "\nThis script provides validation of RHEL-07-010010 V1R3\nto assist with false-positive detection.\n\n"
echo "NOTICE: This script may take a few minutes to run."

for i in $(rpm -Va | awk -F" " '/^.M.........\s./ {print $2}')
do 
    RPMOWNER=$(rpm -qf $i)
    # This is ugly.
    MODESPEC=$(rpm -q ${RPMOWNER} --dump | grep "${i}\ " | awk '{print $5}' | egrep -o "...$")
    TRUEMODE=$(stat -c "%a" ${i})
    LESSPERMS="TRUE!"

    echo -e "\n########################"
    echo "FILENAME: ${i}"
    if [[ ${MODESPEC} -ge ${TRUEMODE} ]]; then echo " !! LESS PERMISSIVE !!"; fi
    echo "| SPEC MODE |  ACTUAL  |"
    echo "|    ${MODESPEC}    |   ${TRUEMODE}    |"
done
