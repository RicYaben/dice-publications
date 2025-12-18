# Measuring What Matters: Revisiting Internet Exposure of OT Networks

This repository contains the configuration files needed to reproduce the results published in the work titled: "Measuring What Matters: Revisiting Internet Exposure of OT Networks".

## Files

- `run.sh`: Main script to start the measurement. Requires the latest version of ZMap (v4.3)installed.
- `bin/zgrab2`: Compiled version of ZGrab2 with probes for IEC 104 and Ethernet/IP.
- `bin/piper`: translation binary to convert ZMap results into ZGrab2 targets.
- `config/zgrab2.ini`: ZGrab2 configuration file for `multi` command.
- `config/zmap_ot.conf`: ZMap configuration file

> [!IMPORTANT] ZGrab2 probes for IEC 104 and Ethernet/IP available at 
> https://github.com/RicYaben/zgrab2.git

## Reproducing the experiment

> [!IMPORTANT] Internet-wide surveys take long times, often >24h
> It is **very** recommended to use a terminal multiplexer (e.g., `tmux`)

1. Create the folders `results` and `logs`
2. Run the following command in your terminal.
```
run.sh ot
```
3. Navigate to `modules`, create a virtual environment and install `dice-mini` and the `modules` requirements
```
python3 -m venv .venv
source .venv/bin/activate
pip install -e dice-mini
pip install -r modules/requirements.txt
```
4. Add the sources
```
dice-mini add \
    -s "results/zgrab2.jsonl zgrab2" \
    -s "resources/enip-vendors.csv enip-vendors" \
    -s "resources/enip-devices.csv enip-devices" \
    -db cs-mwm.db
```
5. Run preliminary commands
```
dice-mini run -C s -M ripe,hosts -db cs-mwm.db
```
6. Classify, fingerprint, and tag
```
dice-mini run cls -db cs-mwm.db
```
7. Post-classification commands (CTI sources)
```
dice-mini run -C s -M greynoise cs-mwm.db
```

## Dataset

- Dataset available upon request
- DOI: https://doi.org/10.5281/zenodo.17977303
