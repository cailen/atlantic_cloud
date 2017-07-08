#!/usr/bin/env bash
wget https://209.208.116.206:4119/software/agent/Ubuntu_16.04/x86_64/ -O /tmp/agent.deb --no-check-certificate --quiet
dpkg -i /tmp/agent.deb
