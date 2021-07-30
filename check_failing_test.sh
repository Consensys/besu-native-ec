#!/bin/bash

FAIL=`grep -s FAIL ./build/results/*.txt`

# if there is more than character in $FAIL, it means there are failing tests
if [ ${#FAIL} -ge 1 ]; then
  echo "There are failing tests"
  exit 1
fi