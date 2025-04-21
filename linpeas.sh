#!/bin/bash

# Download the latest linpeas.sh script
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh

# Make it executable
chmod +x linpeas.sh

# Run linpeas and save the output to linpeas.txt
./linpeas.sh -a > linpeas.txt
