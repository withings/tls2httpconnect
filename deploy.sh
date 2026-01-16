#!/bin/bash

set -e

sudo install -m 0755 tls2httpconnect /usr/local/bin/
sudo systemctl restart tls2httpconnect
