#!/bin/sh
# conwrt-lite overlay library — generate sysupgrade overlay tarballs
[ -n "$_CONWRT_OVERLAY_LOADED" ] && return 0
_CONWRT_OVERLAY_LOADED=1

conwrt_overlay_dhcp_config() {
	_dir="$1"
	mkdir -p "$_dir/etc/config"
	cat > "$_dir/etc/config/dhcp" <<'DHCP_EOF'
config dnsmasq
	option domainneeded '1'
	option localise_queries '1'
	option rebind_protection '1'
	option rebind_localhost '1'
	option local '/lan/'
	option domain 'lan'
	option expandhosts '1'
	option readethers '1'
	option leasefile '/tmp/dhcp.leases'
	option resolvfile '/tmp/resolv.conf.d/resolv.conf.auto'
	option ednspacket_max '1232'

config dhcp 'lan'
	option interface 'lan'
	option ignore '1'

config dhcp 'wan'
	option interface 'wan'
	option ignore '1'

config odhcpd 'odhcpd'
	option maindhcp '0'
	option leasefile '/tmp/hosts/odhcpd'
	option leasetrigger '/usr/sbin/odhcpd-update'
	option loglevel '4'
DHCP_EOF
}

conwrt_overlay_authorized_keys() {
	_dir="$1"
	_pubkey_path="$2"
	mkdir -p "$_dir/etc/dropbear"
	cat "$_pubkey_path" > "$_dir/etc/dropbear/authorized_keys" || {
		echo "failed to read public key from $_pubkey_path" >&2
		return 1
	}
	chmod 600 "$_dir/etc/dropbear/authorized_keys"
}

conwrt_overlay_cleanup() {
	_tmpdir="$1"
	rm -rf "$_tmpdir"
}

conwrt_overlay_build() {
	_output_path="$1"
	_disable_dhcp="$2"
	_authorized_keys_path="$3"

	_tmpdir=$(mktemp -d /tmp/conwrt-overlay-XXXXXX) || {
		echo "failed to create temp directory" >&2
		return 1
	}

	mkdir -p "$_tmpdir/etc/config"
	mkdir -p "$_tmpdir/etc/dropbear"

	if [ "$_disable_dhcp" = "1" ]; then
		conwrt_overlay_dhcp_config "$_tmpdir" || {
			conwrt_overlay_cleanup "$_tmpdir"
			return 1
		}
	fi

	if [ -n "$_authorized_keys_path" ]; then
		conwrt_overlay_authorized_keys "$_tmpdir" "$_authorized_keys_path" || {
			conwrt_overlay_cleanup "$_tmpdir"
			return 1
		}
	fi

	tar czf "$_output_path" -C "$_tmpdir" etc/ || {
		echo "failed to create overlay tarball" >&2
		conwrt_overlay_cleanup "$_tmpdir"
		return 1
	}

	conwrt_overlay_cleanup "$_tmpdir"
	echo "$_output_path"
	return 0
}
