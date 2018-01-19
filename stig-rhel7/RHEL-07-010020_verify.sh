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
# Rule Title:   The cryptographic hash of system files and commands must 
#               match vendor values.
#
# STIG ID:	RHEL-07-010020
# Rule ID:	SV-86479r2_rule
# Vuln ID:	V-71855
# Severity:     CAT I

echo -e "\nThis script provides validation of RHEL-07-010020 V1R3\nto assist with false-positive detection.\n\n"
echo "NOTICE: This script may take a few minutes to run."

for i in $(rpm -Va | awk -F" " '/^..5........\s./ {print $2}')
do 
    RPMOWNER=$(rpm -qf $i)
    MODESPEC=$(rpm -q ${RPMOWNER} --dump | grep "${i}\ " | awk '{print $4}')
    TRUEMODE=$(md5sum ${i} | awk '{print $1}')
    # Not even close to foolproof, but it's something
    CHECKTYPE="$(echo ${i} | egrep -i "(^/etc|^\.|conf(|ig)|cfg|prop(erties|s))")"

    echo -e "\n#######################################################################"
    echo "FILENAME: ${i}"
    if [ ! -z ${CHECKTYPE} ]; then echo -e "                  !! POTENTIAL CONFIGURATION FILE !!"; fi
    echo "|             SPEC MD5             |            ACTUAL MD5            |"
    echo "| ${MODESPEC} | ${TRUEMODE} |"
done
