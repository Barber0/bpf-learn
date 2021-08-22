#!/usr/bin/env bash

sudo apt update
sudo apt -y install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential pkg-config linux-tools-$(uname -r) linux-headers-$(uname -r)