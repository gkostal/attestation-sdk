#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

testdata="${1:?usage: $0 <testdata-root> <capture-work-dir>}"
work="${2:?capture-work-dir must be in the project build tree}"
out="$testdata/offline-collateral"
mkdir -p "$work" "$out/ocsp"
awk -v dir="$work" 'BEGIN{n=0} /-----BEGIN CERTIFICATE-----/{n++}
    {if(n)print > (dir "/cert" n ".pem")}' \
    "$out/rubin-cmw-cert-chain.pem"

entries=()
latest=0
earliest=9223372036854775807
last_next=0
for i in 2 3 4; do
    j=$((i + 1))
    # Existing captures are intentionally reused. Remove cert*.der to recapture.
    if [ -s "$work/cert$i.der" ] && ! openssl ocsp \
        -respin "$work/cert$i.der" -issuer "$work/cert$j.pem" -sha256 \
        -cert "$work/cert$i.pem" -noverify -no_nonce >/dev/null 2>&1; then
        rm "$work/cert$i.der"
    fi
    if [ ! -s "$work/cert$i.der" ]; then
        openssl ocsp -issuer "$work/cert$j.pem" -sha256 \
            -cert "$work/cert$i.pem" -no_nonce -reqout "$work/cert$i.req"
        curl --fail --max-time 60 --silent --show-error \
            -H 'Content-Type: application/ocsp-request' \
            --data-binary "@$work/cert$i.req" https://ocsp.ndis.nvidia.com \
            -o "$work/cert$i.der"
    fi
    text=$(openssl ocsp -respin "$work/cert$i.der" -text -noverify)
    grep -q 'Cert Status: good' <<< "$text"
    hash=$(awk '/Issuer Key Hash:/{print tolower($NF);exit}' <<< "$text")
    serial=$(awk '/Serial Number:/{print tolower($NF);exit}' <<< "$text")
    key="${hash}_${serial}"
    this=$(sed -n 's/^ *This Update: //p' <<< "$text" | head -1)
    produced=$(sed -n 's/^ *Produced At: //p' <<< "$text" | head -1)
    next=$(sed -n 's/^ *Next Update: //p' <<< "$text" | head -1)
    this_epoch=$(date -u -d "$this" +%s)
    produced_epoch=$(date -u -d "$produced" +%s)
    next_epoch=$(date -u -d "$next" +%s)
    (( this_epoch > latest )) && latest=$this_epoch
    (( produced_epoch > latest )) && latest=$produced_epoch
    (( next_epoch < earliest )) && earliest=$next_epoch
    (( next_epoch > last_next )) && last_next=$next_epoch
    cp "$work/cert$i.der" "$out/ocsp/$key.der"
    sha=$(sha256sum "$out/ocsp/$key.der" | cut -d' ' -f1)
    entries+=("{\"lookup_key\":\"$key\",\"this_update\":$this_epoch,\"produced_at\":$produced_epoch,\"next_update\":$next_epoch,\"sha256\":\"$sha\"}")
done
verification=$((latest + 60))
(( verification < earliest ))
{
    printf '{\n  "source": "https://ocsp.ndis.nvidia.com",\n'
    printf '  "verification_time": %s,\n' "$verification"
    printf '  "expired_verification_time": %s,\n' "$((last_next + 60))"
    printf '  "responses": [\n'
    sep=''
    for entry in "${entries[@]}"; do
        printf '%s    %s' "$sep" "$entry"
        sep=$',\n'
    done
    printf '\n  ]\n}\n'
} > "$out/rubin-metadata.json"
