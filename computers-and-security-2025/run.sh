#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

readonly SCAN_PATH=${SCAN_PATH:-"."}
readonly CONF=${CONF:-"config"}
readonly RESULTS=${RESULTS:-"results"}
readonly LOGS=${LOGS:-"logs"}

function dgs::run() {
    local -r conf=$1

    zmap --config="$SCAN_PATH/$CONF/zmap_${conf}.conf" \
        --blocklist-file="$SCAN_PATH/$CONF/blocklist.conf" \
        --output-file="$SCAN_PATH/$RESULTS/zmap_${conf}.jsonl" \
        --log-directory="$SCAN_PATH/$LOGS" \
        --metadata-file="$SCAN_PATH/$LOGS/zmap_${conf}_summary.json"

    ./bin/piper pipe \
        -c $SCAN_PATH/$CONF/zgrab2.ini \
        -i $SCAN_PATH/$RESULTS/zmap_${conf}.jsonl \
        -o $SCAN_PATH/$RESULTS/pipe_${conf}.csv \
        -l $SCAN_PATH/$LOGS/pipe_${conf}.log \
        -w 1000 \
        -f "ip,host,trigger,port"
   
    uniq $SCAN_PATH/$RESULTS/pipe_${conf}.csv > $SCAN_PATH/$RESULTS/zgrab2_${conf}_targets.csv

    ./bin/zgrab2 multiple \
        -c $SCAN_PATH/$CONF/zgrab2.ini \
        -f $SCAN_PATH/$RESULTS/zgrab2_${conf}_targets.csv \
        -o $SCAN_PATH/$RESULTS/zgrab2_${conf}_s1.jsonl \
        -l $SCAN_PATH/$LOGS/zgrab2_${conf}_s1.log \
        --senders=3000 \
        --prometheus="localhost:8000" \
        --flush

    # Scan again for volatility
    ./bin/zgrab2 multiple \
        -c $SCAN_PATH/$CONF/zgrab2.ini \
        -f $SCAN_PATH/$RESULTS/zgrab2_${conf}_targets.csv \
        -o $SCAN_PATH/$RESULTS/zgrab2_${conf}_s2.jsonl \
        -l $SCAN_PATH/$LOGS/zgrab2_${conf}_s2.log \
        --senders=3000 \
        --prometheus="localhost:8000" \
        --flush
}

for i in "$@"; do
    dgs::run $i
done
