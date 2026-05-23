#!/bin/sh
# conwrt-lite inventory library — inventory.jsonl append
[ -n "$_CONWRT_INVENTORY_LOADED" ] && return 0
_CONWRT_INVENTORY_LOADED=1

_CONWRT_INVENTORY_DIR="/tmp/conwrt-lite"
_CONWRT_INVENTORY_FILE="$_CONWRT_INVENTORY_DIR/inventory.jsonl"

conwrt_inventory_append() {
    _json_line="$1"
    mkdir -p "$_CONWRT_INVENTORY_DIR"
    echo "$_json_line" >> "$_CONWRT_INVENTORY_FILE"
}
