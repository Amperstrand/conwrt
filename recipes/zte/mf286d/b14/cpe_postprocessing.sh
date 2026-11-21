#!/bin/sh

PATH=/sbin:/bin:/usr/bin:/usr/sbin

echo "run cpe_postprocessing.sh"

echo "rm -rf /etc_rw/config/tree.xml"
rm -f /etc_rw/config/tree.xml
echo "rm -rf /etc_rw/config/tree_zdm.xml"
rm -f /etc_rw/config/tree_zdm.xml

echo "cpe_postprocessing complete !"



#Set the added and modified parameters
nv set net_select="Only_LTE"
nv set default_lte_band_lock="0x2008080045"
nv set default_gw_band_lock="0x2000000400000"
nv set lte_band_lock="0x2008080045"
nv set gw_band_lock="0x2000000400000"
nv set fota_net_set="1"
nv set cr_version="Nordic_MF286D_B14"
nv set cr_inner_version="CR_TELIAMF286DV1.0.0B14"
nv set integrate_version="TELIA_MF286DV1.0.1B02"
nv set integrate_release_version="TELIA_MF286DV1.0.1B02"
nv set gsspone="ONW2Xh6dWMeFgj4biPKE"
nv set zte_dst_datastall_monitor_switch="1"
nv set DDNSProvider_default="no-ip.com;zoneedit.com;dyndns.org;freedns.afraid.org;"
nv set zte_syslog_enable="1"
nv set syslog_level="1"
nv set syslog_path="/etc_rw/log"
nv set key_local_id="0"
nv set key_syslog_name="key.log"
nv set key_syslog_size="512"
nv set cutoff_detect_switch="1"
nv set cutoff_net_link_detect_url_0="8.8.8.8"
nv set cutoff_net_link_detect_url_1=""
nv set cutoff_net_link_detect_url_2=""
nv set cutoff_net_link_detect_url_3="8.8.8.8"
nv set cutoff_net_link_detect_ping_times="2"
nv set cutoff_net_link_detect_timeout="5"
nv set log_manage_switch="0"

#Set the deleted parameters
nv set https_ServiceURL=""
nv set https_ServiceURL_bk=""
nv set https_ReportServiceURL=""
nv set tcm_server_url=""

#Save the set parameters
nv save
