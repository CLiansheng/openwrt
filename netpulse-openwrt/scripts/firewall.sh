#!/bin/sh

set -eu

TABLE="netpulse"
FAMILY="inet"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

need_nft() {
    command -v nft >/dev/null 2>&1 || fail "nft command not found"
}

valid_word() {
    value="$1"
    shift
    for item in "$@"; do
        [ "$value" = "$item" ] && return 0
    done
    return 1
}

valid_ip() {
    value="$1"
    [ -z "$value" ] && return 0
    [ "$value" = "any" ] && return 0
    echo "$value" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$' || return 1
    addr="${value%%/*}"
    old_ifs="$IFS"
    IFS=.
    set -- $addr
    IFS="$old_ifs"
    [ "$#" -eq 4 ] || return 1
    for octet in "$@"; do
        [ "$octet" -ge 0 ] && [ "$octet" -le 255 ] || return 1
    done
    if echo "$value" | grep -q '/'; then
        prefix="${value#*/}"
        [ "$prefix" -ge 0 ] && [ "$prefix" -le 32 ] || return 1
    fi
    return 0
}

valid_port() {
    value="$1"
    [ -z "$value" ] && return 0
    [ "$value" = "any" ] && return 0
    echo "$value" | grep -Eq '^[0-9]+$' || return 1
    [ "$value" -ge 1 ] && [ "$value" -le 65535 ]
}

ensure_table() {
    need_nft
    nft list table "$FAMILY" "$TABLE" >/dev/null 2>&1 || nft add table "$FAMILY" "$TABLE"
    nft list chain "$FAMILY" "$TABLE" input >/dev/null 2>&1 || \
        nft add chain "$FAMILY" "$TABLE" input "{ type filter hook input priority -5; policy accept; }"
    nft list chain "$FAMILY" "$TABLE" forward >/dev/null 2>&1 || \
        nft add chain "$FAMILY" "$TABLE" forward "{ type filter hook forward priority -5; policy accept; }"
}

append_match() {
    proto="$1"
    src="$2"
    dst="$3"
    port="$4"
    match=""

    case "$proto" in
        tcp|udp) match="$match meta l4proto $proto" ;;
        icmp) match="$match ip protocol icmp" ;;
        all) ;;
        *) fail "invalid protocol" ;;
    esac

    if [ -n "$src" ] && [ "$src" != "any" ]; then
        match="$match ip saddr $src"
    fi
    if [ -n "$dst" ] && [ "$dst" != "any" ]; then
        match="$match ip daddr $dst"
    fi
    if [ -n "$port" ] && [ "$port" != "any" ]; then
        [ "$proto" = "tcp" ] || [ "$proto" = "udp" ] || fail "port requires tcp or udp"
        match="$match $proto dport $port"
    fi

    echo "$match"
}

cmd_add() {
    [ "$#" -eq 5 ] || fail "usage: firewall.sh add proto src dst port action"
    proto="$1"
    src="$2"
    dst="$3"
    port="$4"
    action="$5"

    valid_word "$proto" all tcp udp icmp || fail "invalid protocol"
    valid_word "$action" accept reject drop || fail "invalid action"
    valid_ip "$src" || fail "invalid source address"
    valid_ip "$dst" || fail "invalid destination address"
    valid_port "$port" || fail "invalid port"

    ensure_table
    id="$(date +%s)"
    match="$(append_match "$proto" "$src" "$dst" "$port")"

    nft add rule "$FAMILY" "$TABLE" input $match counter "$action" comment "netpulse:$id"
    nft add rule "$FAMILY" "$TABLE" forward $match counter "$action" comment "netpulse:$id"

    echo "added rule id: $id"
    echo "protocol=$proto src=$src dst=$dst port=$port action=$action"
}

cmd_list() {
    ensure_table
    nft -a list table "$FAMILY" "$TABLE"
}

cmd_clear() {
    ensure_table
    nft flush chain "$FAMILY" "$TABLE" input
    nft flush chain "$FAMILY" "$TABLE" forward
    echo "all netpulse rules cleared"
}

delete_from_chain() {
    chain="$1"
    id="$2"
    handles="$(nft -a list chain "$FAMILY" "$TABLE" "$chain" | awk -v needle="netpulse:$id" '
        index($0, needle) {
            for (i = 1; i <= NF; i++) {
                if ($i == "handle") print $(i + 1)
            }
        }
    ')"
    for handle in $handles; do
        nft delete rule "$FAMILY" "$TABLE" "$chain" handle "$handle"
        echo "deleted $chain handle $handle"
    done
}

cmd_delete() {
    [ "$#" -eq 1 ] || fail "usage: firewall.sh delete id"
    id="$1"
    echo "$id" | grep -Eq '^[0-9]+$' || fail "invalid id"
    ensure_table
    delete_from_chain input "$id"
    delete_from_chain forward "$id"
}

case "${1:-}" in
    add)
        shift
        cmd_add "$@"
        ;;
    list)
        shift
        cmd_list "$@"
        ;;
    clear)
        shift
        cmd_clear "$@"
        ;;
    delete)
        shift
        cmd_delete "$@"
        ;;
    *)
        fail "usage: firewall.sh {add|list|clear|delete}"
        ;;
esac
