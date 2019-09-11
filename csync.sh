#!/usr/bin/env bash
while getopts ":s:d:m:" opt; do
    case "$opt" in
        s) src=$OPTARG ;;
        d) dst=$OPTARG ;;
        m) mons=$OPTARG ;;
    esac
done

for mon in $mons; do
    monsrc="${src//%MON/$mon}"
    mondst="${dst//%MON/$mon}"
    echo "scp $monsrc $mondst"
    scp $monsrc $mondst
    exit_status=$
    if [ $exit_status -ne 0 ]; then
        echo "$mon failed"
    else
        scp 
    fi
done