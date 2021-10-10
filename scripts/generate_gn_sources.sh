#!/bin/sh

echo "sources = ["

shopt -s nullglob

for file in *.c *.cpp *.S; do
    echo "\"$file\","
done

echo "]"
