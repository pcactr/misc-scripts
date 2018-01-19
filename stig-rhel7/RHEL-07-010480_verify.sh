#!/bin/bash
#
# Author: paul.c.arnold4.ctr@mail.mil
#
# The DISA check is incorrect as there is white-space before
# the declaration --
#
#     This will not return anything on properly-configured RHEL7
#     installations:
#
#         # grep -i ^password_pbkdf2 /boot/grub2/grub.cfg
#
#
#
## DISA Stuff ##
#
# STIG Release: Red Hat Enterprise Linux 7 Security Technical Implementation
#               Guide - Version 1 - Release 3
#
# Rule Title:   Systems with a Basic Input/Output System (BIOS) must require 
#               authentication upon booting into single-user and maintenance 
#               modes.
#
# STIG ID:      RHEL-07-010480
# Rule ID:      SV-86585r3_rule
# Vuln ID:      V-71961
# Severity:     CAT I
#
#

if [ ! -e /boot/grub2/grub.cfg ]; then
    echo "Cannot find BIOS-based GRUB2 config file."
    exit 1
elif [ -e /boot/efi/EFI/redhat/grub.cfg ]; then
    echo "This appears to be a UEFI system. This check is not applicable."
    exit 1
fi

# This ensures it picks up any declarations of password_pbkdf2
# even if it has white-space before it.
GRUBCFGHASH="$(awk '/^\s+password_pbkdf2/ {print $3}' /boot/grub2/grub.cfg)"

# If GRUBCFGHASH returned not-null and the hash exists in grub.cfg, print
if [ -n ${GRUBCFGHASH} ] && [ $(grep "grub.pbkdf2.sha512" /boot/grub2/grub.cfg) ]; then
    echo ${GRUBCFGHASH}
# if GRUBCFGHASH returned not-null and the hash didn't exist in grub.cfg, check user.cfg
elif [ -n ${GRUBCFGHASH} ] && [ ! $(grep "grub.pbkdf2.sha512" /boot/grub2/grub.cfg) ];then
    grep "grub.pbkdf2.sha512" /boot/grub2/user.cfg
fi
