#!/bin/bash

cat verifier.sol | grep '<%' | cut -f2 -d'<' | cut -f1 -d'>' | sort | uniq -c | sort -nr > verifier.todo
