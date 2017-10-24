#!/bin/bash

while IFS='' read -r line || [[ -n "$line" ]]; do
  f=$(find . -name $line*)
  echo $f
done < "$1"
