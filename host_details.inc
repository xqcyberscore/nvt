###############################################################################
# OpenVAS Vulnerability Test
# $Id: host_details.inc 10573 2018-07-23 10:44:26Z cfischer $
#
# Centralized and organized host information base
#
# Authors:
# Henri Doreau <henri.doreau@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
# $Revision: 10573 $
#
###############################################################################

# Those are for debugging purposes (see get_app_version() and get_app_location())
global_var _get_app_version_used, _get_app_location_used;

##
# This script exports a function to store host information in a structured
# way.
#
# <host>
#   <detail>
#     <name>OS</name>
#     <value>Debian</value>
#     <method>
#       <nvt>1.2.3.4.5.6</nvt>
#       <description>NVT description</description>
#     </method>
#   </detail>
#   <detail>
#     <name>OS</name>
#     <value>cpe:/o:debian_linux:debian:5.0</value>
#     <method>
#       <nvt>1.2.3.4</nvt>
#       <description>another NVT description</description>
#     </method>
#   </detail>
# </host>
#
#
#
# For this example, we would use these KB entries:
# ------------------------------------------------
#
# HostDetails                     => "OS"
# HostDetails/NVT                 => "1.2.3.4.5.6", "1.2.3.4"
# --
# HostDetails/NVT/1.2.3.4.5.6     => "NVT Description"
# HostDetails/NVT/1.2.3.4.5.6/OS  => "Debian"
# --
# HostDetails/NVT/1.2.3.4         => "another NVT description"
# HostDetails/NVT/1.2.3.4/OS      => "cpe:/o:debian_linux:debian:5.0"
##

include("xml.inc");

# Best OS detection sources, sorted by decreasing accuracy (best is first).
OS_CPE_SRC = make_list(
    "1.3.6.1.4.1.25623.1.0.103220", # gb_greenbone_os_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105383", # gb_ami_megarac_sp_web_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103633", # gb_ros_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103628", # gb_apple_mobile_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103418", # gb_vmware_esx_web_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103417", # gb_vmware_esx_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.96206",  # gb_ssh_cisco_ios_get_version.nasl
    "1.3.6.1.4.1.25623.1.0.105544", # gb_cisco_cucmim_version.nasl
    "1.3.6.1.4.1.25623.1.0.105540", # gb_cisco_cucm_version.nasl
    "1.3.6.1.4.1.25623.1.0.105690", # gb_cisco_nx_os_version.nasl
    "1.3.6.1.4.1.25623.1.0.105068", # gb_cyclades_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105313", # gb_fortios_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105440", # gb_cisco_esa_version.nasl
    "1.3.6.1.4.1.25623.1.0.105441", # gb_cisco_wsa_version.nasl
    "1.3.6.1.4.1.25623.1.0.105433", # gb_cisco_csma_version.nasl
    "1.3.6.1.4.1.25623.1.0.105533", # gb_cisco_ip_phone_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105532", # gb_cisco_ios_xr_version.nasl
    "1.3.6.1.4.1.25623.1.0.96200",  # gb_ssh_junos_get_version.nasl
    "1.3.6.1.4.1.25623.1.0.105263", # gb_palo_alto_panOS_version.nasl
    "1.3.6.1.4.1.25623.1.0.105266", # gb_screenos_version.nasl
    "1.3.6.1.4.1.25623.1.0.106413", # gb_extremeos_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106513", # gb_cisco_asa_version_snmp.nasl
    "1.3.6.1.4.1.25623.1.0.105222", # gb_cisco_asa_version.nasl
    "1.3.6.1.4.1.25623.1.0.106494", # gb_arista_eos_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108307", # gb_netgear_prosafe_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.108311", # gb_hirschmann_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.810608", # gb_mikrotik_router_routeros_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105144", # gb_xenserver_version.nasl
    "1.3.6.1.4.1.25623.1.0.105659", # gb_cisco_ios_xe_version.nasl
    "1.3.6.1.4.1.25623.1.0.105155", # gb_mcafee_email_gateway_version.nasl
    "1.3.6.1.4.1.25623.1.0.140058", # gb_brocade_netiron_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108335", # gb_brocade_fabricos_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105244", # gb_arubaos_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106864", # gb_cyberoam_umt_ngfw_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106875", # gb_aerohive_hiveos_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103875", # gb_qnap_nas_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103786", # gb_synology_dsm_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106096", # gb_simatic_s7_version.nasl
    "1.3.6.1.4.1.25623.1.0.140738", # gb_simatic_cp_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.140748", # gb_simatic_scalance_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.140811", # gb_siemens_ruggedcom_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.20285",  # ilo_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106078", # gb_watchguard_fireware_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108338", # gb_vibnode_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.108347", # gb_hyperip_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.96207",  # gb_windows_cpe_detect.nasl
    "1.3.6.1.4.1.25623.1.0.50282",  # gather-package-list.nasl
    "1.3.6.1.4.1.25623.1.0.105614", # gb_cisco_pis_version.nasl
    "1.3.6.1.4.1.25623.1.0.140454", # gb_checkpoint_fw_version.nasl
    "1.3.6.1.4.1.25623.1.0.103621", # gb_smb_windows_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112309", # gb_nec_communication_platforms_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105586", # gb_ssh_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.104000", # nmap_net.nasl
    "1.3.6.1.4.1.25623.1.0.103809", # gb_junos_snmp_version.nasl
    "1.3.6.1.4.1.25623.1.0.105271", # gb_citrix_netscaler_version.nasl
    "1.3.6.1.4.1.25623.1.0.103429", # gb_snmp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108014", # gb_dns_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.105355", # gb_ftp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.102011", # smb_nativelanman.nasl
    "1.3.6.1.4.1.25623.1.0.103979", # gb_ucs_detect.nasl
    "1.3.6.1.4.1.25623.1.0.111067", # sw_http_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.111068", # sw_mail_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.111069", # sw_telnet_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108192", # gb_mysql_mariadb_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.10884",  # ntp_open.nasl
    "1.3.6.1.4.1.25623.1.0.101013", # remote-detect-MDNS.nasl
    "1.3.6.1.4.1.25623.1.0.10144",  # mssqlserver_detect.nasl
    "1.3.6.1.4.1.25623.1.0.140000", # gb_apple_tv_version.nasl
    "1.3.6.1.4.1.25623.1.0.105899", # gb_apple_tv_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108200", # gb_upnp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108201", # gb_sip_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.140096", # gb_check_mk_agent_detect.nasl
    "1.3.6.1.4.1.25623.1.0.100062", # ms_rdp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105330", # gb_apache_activemq_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108044", # dcetest.nasl
    "1.3.6.1.4.1.25623.1.0.108284", # gb_hnap_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.14674",  # ident_process_owner.nasl
    "1.3.6.1.4.1.25623.1.0.108342", # gb_pihole_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105112", # gb_dropbear_ssh_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108451", # gb_rtsp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108447", # gb_android_adb_detect.nasl nb: Down here because an ADB service could be run on an Android emulator as well...
    "1.3.6.1.4.1.25623.1.0.108021", # gb_nmap_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.102002"  # os_fingerprint.nasl
);

OS_TXT_SRC = make_list(
    "1.3.6.1.4.1.25623.1.0.103220", # gb_greenbone_os_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105383", # gb_ami_megarac_sp_web_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103633", # gb_ros_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103628", # gb_apple_mobile_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103418", # gb_vmware_esx_web_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103417", # gb_vmware_esx_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.96206",  # gb_ssh_cisco_ios_get_version.nasl
    "1.3.6.1.4.1.25623.1.0.105544", # gb_cisco_cucmim_version.nasl
    "1.3.6.1.4.1.25623.1.0.105540", # gb_cisco_cucm_version.nasl
    "1.3.6.1.4.1.25623.1.0.105690", # gb_cisco_nx_os_version.nasl
    "1.3.6.1.4.1.25623.1.0.105068", # gb_cyclades_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105313", # gb_fortios_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105440", # gb_cisco_esa_version.nasl
    "1.3.6.1.4.1.25623.1.0.105441", # gb_cisco_wsa_version.nasl
    "1.3.6.1.4.1.25623.1.0.105433", # gb_cisco_csma_version.nasl
    "1.3.6.1.4.1.25623.1.0.105533", # gb_cisco_ip_phone_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105532", # gb_cisco_ios_xr_version.nasl
    "1.3.6.1.4.1.25623.1.0.96200",  # gb_ssh_junos_get_version.nasl
    "1.3.6.1.4.1.25623.1.0.105263", # gb_palo_alto_panOS_version.nasl
    "1.3.6.1.4.1.25623.1.0.105266", # gb_screenos_version.nasl
    "1.3.6.1.4.1.25623.1.0.106413", # gb_extremeos_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106513", # gb_cisco_asa_version_snmp.nasl
    "1.3.6.1.4.1.25623.1.0.105222", # gb_cisco_asa_version.nasl
    "1.3.6.1.4.1.25623.1.0.106494", # gb_arista_eos_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106875", # gb_aerohive_hiveos_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103875", # gb_qnap_nas_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103786", # gb_synology_dsm_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106096", # gb_simatic_s7_version.nasl
    "1.3.6.1.4.1.25623.1.0.140738", # gb_simatic_cp_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.140748", # gb_simatic_scalance_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.140811", # gb_siemens_ruggedcom_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.20285",  # ilo_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106078", # gb_watchguard_fireware_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108307", # gb_netgear_prosafe_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.108311", # gb_hirschmann_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.810608", # gb_mikrotik_router_routeros_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105144", # gb_xenserver_version.nasl
    "1.3.6.1.4.1.25623.1.0.105659", # gb_cisco_ios_xe_version.nasl
    "1.3.6.1.4.1.25623.1.0.105155", # gb_mcafee_email_gateway_version.nasl
    "1.3.6.1.4.1.25623.1.0.140058", # gb_brocade_netiron_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108335", # gb_brocade_fabricos_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.105244", # gb_arubaos_detect.nasl
    "1.3.6.1.4.1.25623.1.0.106864", # gb_cyberoam_umt_ngfw_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108338", # gb_vibnode_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.108347", # gb_hyperip_consolidation.nasl
    "1.3.6.1.4.1.25623.1.0.96207",  # gb_windows_cpe_detect.nasl
    "1.3.6.1.4.1.25623.1.0.50282",  # gather-package-list.nasl
    "1.3.6.1.4.1.25623.1.0.105614", # gb_cisco_pis_version.nasl
    "1.3.6.1.4.1.25623.1.0.140454", # gb_checkpoint_fw_version.nasl
    "1.3.6.1.4.1.25623.1.0.103621", # gb_smb_windows_detect.nasl
    "1.3.6.1.4.1.25623.1.0.112309", # gb_nec_communication_platforms_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105586", # gb_ssh_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.104000", # nmap_net.nasl
    "1.3.6.1.4.1.25623.1.0.105271", # gb_citrix_netscaler_version.nasl
    "1.3.6.1.4.1.25623.1.0.103809", # gb_junos_snmp_version.nasl
    "1.3.6.1.4.1.25623.1.0.103429", # gb_snmp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108014", # gb_dns_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.105355", # gb_ftp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.102011", # smb_nativelanman.nasl
    "1.3.6.1.4.1.25623.1.0.103979", # gb_ucs_detect.nasl
    "1.3.6.1.4.1.25623.1.0.111067", # sw_http_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.111068", # sw_mail_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.111069", # sw_telnet_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108192", # gb_mysql_mariadb_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.10884",  # ntp_open.nasl
    "1.3.6.1.4.1.25623.1.0.101013", # remote-detect-MDNS.nasl
    "1.3.6.1.4.1.25623.1.0.10144",  # mssqlserver_detect.nasl
    "1.3.6.1.4.1.25623.1.0.140000", # gb_apple_tv_version.nasl
    "1.3.6.1.4.1.25623.1.0.105899", # gb_apple_tv_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108200", # gb_upnp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108201", # gb_sip_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.140096", # gb_check_mk_agent_detect.nasl
    "1.3.6.1.4.1.25623.1.0.100062", # ms_rdp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105330", # gb_apache_activemq_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108044", # dcetest.nasl
    "1.3.6.1.4.1.25623.1.0.108284", # gb_hnap_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.14674",  # ident_process_owner.nasl
    "1.3.6.1.4.1.25623.1.0.108342", # gb_pihole_detect.nasl
    "1.3.6.1.4.1.25623.1.0.105112", # gb_dropbear_ssh_detect.nasl
    "1.3.6.1.4.1.25623.1.0.108451", # gb_rtsp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.108447", # gb_android_adb_detect.nasl nb: Down here because an ADB service could be run on an Android emulator as well...
    "1.3.6.1.4.1.25623.1.0.108021", # gb_nmap_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.102002"  # os_fingerprint.nasl
);

function register_host_detail( name, value, desc ) {

  local_var name, value, desc, nvt, tokens;

  if( ! name ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#name#-#register_host_detail" );
  if( ! value ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#value#-#register_host_detail" );

  nvt = get_script_oid();
  if( ! nvt ) return;

  if(name != "port") {
    set_kb_item(name:"HostDetails", value:name);
    set_kb_item(name:"HostDetails/NVT", value:nvt);
    if (!isnull(desc))
      replace_kb_item(name:"HostDetails/NVT/" + nvt, value:desc);
  }

  if(value)
    set_kb_item(name:"HostDetails/NVT/" + nvt + "/" + name, value:value);

  # gather-package-list.nasl sets precise OS CPE keys that we use to
  # efficiently schedule LSCs.
  if (name == "OS" && "cpe:/o:" >< value && nvt == "1.3.6.1.4.1.25623.1.0.50282") {
    tokens = split(value, sep:":", keep:FALSE);

    if (tokens && tokens[0] && tokens[1] && tokens[2] && tokens[3])
      set_kb_item(name:string("HostDetails/OS/", tokens[0], ":", tokens[1], ":",
                              tokens[2], ":", tokens[3]), value:TRUE);
  }
}

function register_product( cpe, location, port, proto, service ) {

  local_var cpe, location, port, proto, service, kb_e, base_cpe;

  register_host_detail( name:"App", value:cpe );
  register_host_detail( name:cpe, value:location );
  if( port ) {
    register_host_detail( name:"port", value:port );
  }

  # store an entry under the "base" cpe, so we could fork later for each entry under a cpe
  if( ! base_cpe = get_base_cpe( cpe:cpe ) ) {
    set_kb_item( name:"nvt_debug_cpe_syntax/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#register_product" );
    base_cpe = cpe;
  }

  if( ! proto ) proto = "tcp";

  if( service )
    kb_e = get_script_oid() + '#-#' + cpe + '#-#' + location + '#-#' + port + '#-#' + proto + '#-#' + service;
  else
    kb_e = get_script_oid() + '#-#' + cpe + '#-#' + location + '#-#' + port + '#-#' + proto;

  set_kb_item( name:'get_app/' + base_cpe, value:kb_e );

  if( ! isnull( port ) ) {
    if( port == 0 ) {
      set_kb_item( name:'get_app/ports/' + base_cpe, value:"local" ); # For products identified locally. We currently can't set a value of 0 here
    } else {
      set_kb_item( name:'get_app/ports/' + base_cpe, value:port );
    }

    set_kb_item( name:'get_app/protocols/' + base_cpe, value:proto );

    if( service )
      set_kb_item( name:'get_app/services/' + port + "/" + base_cpe, value:service );
  }
}

# provided for conveniency: host_details_list("OS")
function host_details_list(key) {
  return get_kb_list("HostDetails/NVT/*/" + key);
}

function report_host_detail_single( name, value, nvt, desc ) {

  local_var name, value, nvt, desc, report;

  if( ! name ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#name#-#report_host_detail_single" );
  if( ! value ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#value#-#report_host_detail_single" );
  if( ! nvt ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#nvt#-#report_host_detail_single" );

  report = '';

  report += xml_open_tag(tag:'host');
  report += xml_open_tag(tag:'detail');
  report += xml_tagline(tag:'name', value:name);
  report += xml_tagline(tag:'value', value:value);
  report += xml_open_tag(tag:'source');
  report += xml_tagline(tag:'type', value:"nvt");
  report += xml_tagline(tag:'name', value:nvt);

  if (!isnull(desc))
    report += xml_tagline(tag:'description', value:desc);
  else
    report += '<description/>';

  report += xml_close_tag(tag:'source');
  report += xml_close_tag(tag:'detail');
  report += xml_close_tag(tag:'host');

  log_message(proto:"Host_Details", data:report);
}

# Iterate over the host details and report them individually. Additionally
# report best CPE and TXT available concerning the remote OS.
function report_host_details() {

  local_var names, name, nvts, nvt, desc, details, item;

  # get the names of the host details we gathered
  names = get_kb_list("HostDetails");

  # list of concerned NVTs
  nvts = get_kb_list("HostDetails/NVT");
  foreach nvt (nvts) {
    # description of the current NVT
    desc = get_kb_item("HostDetails/NVT/" + nvt);

    # iterate over the registered entries...
    foreach name (names) {
      details = get_kb_list("HostDetails/NVT/" + nvt + "/" + name);

      # add a section in case the current NVT has some value for this entry
      foreach item (details) {
        if (!isnull(item)) {
          report_host_detail_single(name:name, value:item, nvt:nvt, desc:desc);
        }
      }
    }
  }

  # Report best OS entries
  report_best_os_cpe();
  report_best_os_txt();
}

function host_runs() {

  local_var ospattern, best_os;

  ospattern = _FCT_ANON_ARGS[0];
  if( ! ospattern ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#_FCT_ANON_ARGS[0]#-#host_runs" );

  #TBD/TODO: What if "best_os_txt" is "better" then "best_os_cpe"?
  best_os = best_os_cpe();
  if( isnull( best_os ) ) {
    best_os = best_os_txt();
    if( isnull( best_os ) ) return "unknown";
  }

  #nb: update this to include possible cpes and txt from ssh_detect.nasl, gb_ssh_os_detection.nasl, gather-package-list.nasl and other *_os_detection.nasl
  if( "linux" >< tolower( ospattern ) )
    ospattern = '(' + ospattern + '|apc:aos|ubuntu|debian|bsd|opensuse|fedora|suse|redhat|red hat|centos|mandriva|mandrake|mageia|slackware|connectiva|amazon|oracle|' +
                'turbolinux|gentoo|cisco|apple|fortios|junos|screenos|univention|esx|xen|panos|pan-os|qnap|synology|greenbone|hyperip|simatic|ruggedcom|vibnode)';

  if( eregmatch( pattern:ospattern, string:best_os, icase:TRUE ) )
    return "yes";

  return "no";
}

function best_os_cpe() {

  local_var oid, res, entry;

  foreach oid (OS_CPE_SRC) {
    res = get_kb_list("HostDetails/NVT/" + oid + "/OS");
    if (!isnull(res)) {
      res = make_list(res);
      foreach entry (res) {
        # both CPE and free-form entries can be registered under the "OS" banner
        if ("cpe:/" >< entry)
          return entry;
      }
    }
  }
  return NULL;
}

function best_os_txt() {

  local_var oid, res, entry;

  foreach oid (OS_TXT_SRC) {
    res = get_kb_list("HostDetails/NVT/" + oid + "/OS");
    if (!isnull(res)) {
      res = make_list(res);
      foreach entry (res) {
        # both CPE and free-form entries can be registered under the "OS" banner
        if ("cpe:/" >!< entry)
          return entry;
      }
    }
  }
  return NULL;
}

function report_best_os_cpe() {

  local_var best_os, desc;

  best_os = get_kb_item("HostDetails/OS/BestMatch");
  if (best_os) {
    desc = get_kb_item("HostDetails/OS/BestMatch/Details");
    desc = split(desc, sep:";");
    report_host_detail_single(name:"best_os_cpe", value:best_os, nvt:desc[0], desc:desc[1]);
    return;
  }
}

function report_best_os_txt() {

  local_var oid, res, best_os, desc;

  foreach oid (OS_TXT_SRC) {
    res = get_kb_list("HostDetails/NVT/" + oid + "/OS");

    if (!isnull(res)) {
      res = make_list(res);

      foreach best_os (res) {

        # discard CPE entries
        if ("cpe:/" >< best_os)
          continue;

        # in case we have several entries from this script...
        if (os_conflict(res, best_os))
          best_os = best_os + ' [possible conflict]';

        desc = get_kb_item("HostDetails/NVT/" + oid);
        report_host_detail_single(name:"best_os_txt", value:best_os, nvt:oid, desc:desc);
        return;
      }
    }
  }
}

function host_details_cpes() {

  local_var res, details_list, item;

  res = make_list();

  # get all the registered entries for applications
  details_list = host_details_list(key:"App");

  if (!isnull(details_list))
    foreach item (details_list)
      if ("cpe:/" >< item)
        res = make_list(res, item);

  # get the best CPE we have for operating system (if any)
  item = best_os_cpe();
  if (!isnull(item))
    res = make_list(res, item);

  return res;
}

function os_conflict() {

  local_var oslist, bestos, is_cpe, item;

  oslist = _FCT_ANON_ARGS[0];
  bestos = _FCT_ANON_ARGS[1];

  is_cpe = FALSE;

  if ("cpe:/" >< bestos)
    is_cpe = TRUE;

  foreach item (oslist) {
    if (item == bestos)
      continue;

    # return true if the list contains at least one element of the same type (cpe or text)
    if (("cpe:/" >< item) == is_cpe)
      return TRUE;
  }
  return FALSE;
}

function get_app( cpe, loc ) {

  local_var host_details, host_detail, res, port, cpe, loc, l, host_values;

  if( ! cpe ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe[0]#-#get_app" );

  host_details = get_kb_list("HostDetails/NVT/*");

  if(!host_details) return NULL;

  foreach host_detail (keys(host_details)) {

    if(cpe >< host_detail) {

      host_values = split(host_detail, sep:"/", keep:FALSE);

      if(isnull(host_values[2]) || isnull(host_values[4]) || "cpe:" >!< host_values[3]) return NULL;

      res = make_array();

      res["OID"] = host_values[2];
      res["CPE"] = 'cpe:/' +  host_values[4];

      port = get_kb_item("HostDetails/NVT/" + res["OID"] + "/port");  # this could fork

      if(port) {
        res["port"] = port;
      }

      if(loc) {
        location = get_kb_item("HostDetails/NVT/" + res["OID"] + "/" + res["CPE"]); # this could fork
        res["LOCATION"] = location;
      } else {
        locations = get_kb_list("HostDetails/NVT/" + res["OID"] + "/" + res["CPE"]);
        l = make_list(locations);
        if(max_index(l) == 1) location = l[0];
      }

      # Store link between scripts.
      register_host_detail(name:"detected_by", value:res["OID"]);
      register_host_detail(name:"detected_at", value:location);

      return res;
    }
  }
  return NULL;
}

# *NEVER* use get_app_version() and get_app_location() together in a single NVT.
# If both information is required, use get_app_version_and_location() or
# get_app_full()

#
# register_product( cpe:'cpe:/a:foo:bar:1.1.0', location:"/foo", port: 80);
# register_product( cpe:'cpe:/a:foo:bar:1.2.0', location:"/bar", port: 80);
# register_product( cpe:'cpe:/a:foo:bar:1.3.0', location:"/foobar", port: 8080);
#                                                                                                                           ,--[1.1.0]
#                                                 ,--[ 80 ] -> get_app_version( cpe:'cpe:/a:foo:bar', port:80  ) -> fork -> |
#                                                 |                                                                         `--[1.2.0]
# get_app_port( cpe:'cpe:/a:foo:bar' ) -> fork -> |
#                                                 `--[8080] -> get_app_version( cpe:'cpe:/a:foo:bar', port:8080 ) -> [1.3.0]
# Without port:
#
#                                                    ,--[1.1.0]
# get_app_version( cpe:'cpe:/a:foo:bar' ) -> fork -> |
#                                                    |--[1.2.0]
#                                                    |
#                                                    `--[1.3.0]
#
#
#                                                                                                                            ,--[/foo]
#                                                 ,--[ 80 ] -> get_app_location( cpe:'cpe:/a:foo:bar', port:80  ) -> fork -> |
#                                                 |                                                                          `--[/bar]
# get_app_port( cpe:'cpe:/a:foo:bar' ) -> fork -> |
#                                                 `--[8080] -> get_app_location( cpe:'cpe:/a:foo:bar', port:8080 ) -> [/foobar]
#
# Without port:
#                                                     ,--[/foo]
# get_app_location( cpe:'cpe:/a:foo:bar' ) -> fork -> |
#                                                     |--[/bar]
#                                                     |
#                                                     `--[/foobar]
#
#
#                                                                                                                                        ,-> array -> ( [version:1.1.0] [location:/foo] )
#                                                 ,--[ 80 ] -> get_app_version_and_location( cpe:'cpe:/a:foo:bar', port:80  ) -> fork -> |
#                                                 |                                                                                      `-> array -> ( [version:1.2.0] [location:bar] )
# get_app_port( cpe:'cpe:/a:foo:bar' ) -> fork -> |
#                                                 `--[8080] -> get_app_version_and_location( cpe:'cpe:/a:foo:bar', port:8080 ) -> array -> ( [version:1.3.0] [location:/foobar] )
# Without port:
#
#                                                                 ,-> array -> ( [version:1.1.0] [location:/foo] )
# get_app_version_and_location( cpe:'cpe:/a:foo:bar' ) -> fork -> |
#                                                                 |-> array -> ( [version:1.2.0] [location:/bar] )
#                                                                 |
#                                                                 `-> array -> ( [version:1.3.0] [location:/foobar] )
#


function get_app_version( cpe, port, service, nofork, version_regex ) {

  local_var cpe, port, service, nofork, version_regex;

  # To report if get_app_version() and get_app_location() is used together in one single NVT
  _get_app_version_used = TRUE;
  if( _get_app_location_used ) {
    set_kb_item( name:"nvt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#get_app_version() used together with get_app_location() in one single NVT. Please use get_app_version_and_location instead." );
  }

  if( ! cpe ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_app_version" );

  if( typeof( cpe ) == "array" ) return get_single_app_version_from_list( cpe_list:cpe, port:port );

  return get_app_details( cpe:cpe, typ:"version", port:port, service:service, nofork:nofork, version_regex:version_regex );
}

# nb: If you use this you need to include revisions-lib.inc
function get_highest_app_version( cpe ) {

  local_var cpe, ad, version, ret_version;

  if( ! cpe ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_highest_app_version" );

  ad = get_app_details( cpe:cpe, typ:"all_versions" );
  if( ! ad ) return;

  ret_version = FALSE;

  foreach version ( ad )
  {
    if( ! ret_version )
    {
      ret_version = version;
      continue;
    }

    # from revisions-lib.inc
    if( revcomp( a:version, b:ret_version ) == 1 )
      ret_version = version;
  }

  return ret_version;
}

function get_app_location( cpe, port, nofork, skip_port ) {

  local_var cpe, port, nofork, skip_port;

  # To report if get_app_version() and get_app_location() is used together in one single NVT
  _get_app_location_used = TRUE;
  if( _get_app_version_used ) {
    set_kb_item( name:"nvt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#get_app_version() used together with get_app_location() in one single NVT. Please use get_app_version_and_location instead." );
  }

  if( ! cpe ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_app_location" );
  if( ! port && ! nofork && ! skip_port ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#get_app_location" );

  return get_app_details( cpe:cpe, typ:"location", port:port, nofork:nofork );
}

function get_single_app_port_from_list( cpe_list, service ) {

  local_var cpe_list, service, cpe, base_cpe, port, services;

  if( ! cpe_list ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe_list#-#get_single_app_port_from_list" );

  foreach cpe( cpe_list ) {
    if( ! base_cpe = get_base_cpe( cpe:cpe ) )
      continue;

    if( isnull( port = get_kb_item( "get_app/ports/" + base_cpe ) ) )
      continue;

    if( service ) {
      services = get_kb_item( "get_app/services/" + port + "/" + base_cpe ); # this could fork
      if( port =~ '^[0-9]{1,5}$' && services >< service ) return port;
    } else {
      if( port =~ '^[0-9]{1,5}$' ) return port;
    }
  }
  return;
}

function get_all_app_port_from_list( cpe_list, service ) {

  local_var cpe_list, service, cpe, base_cpe, _port, _ports, services, _service, infos, _infos, ret_arr;

  if( ! cpe_list ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe_list#-#get_all_app_port_from_list" );

  foreach cpe( cpe_list ) {

    if( ! base_cpe = get_base_cpe( cpe:cpe ) )
      continue;

    if( isnull( _ports = get_kb_list( "get_app/ports/" + base_cpe ) ) )
      continue;

    foreach _port( _ports ) {
      if( service ) {
        services = get_kb_list( "get_app/services/" + _port + "/" + base_cpe );
        foreach _service( services ) {
          if( _port =~ '^[0-9]{1,5}$' && _service >< service ) set_kb_item( name:"get_app/" + get_script_oid() + "/port_cpe", value:cpe + "#-#" + _port );
        }
      } else {
        if( _port =~ '^[0-9]{1,5}$' ) set_kb_item( name:"get_app/" + get_script_oid() + "/port_cpe", value:cpe + "#-#" + _port );
      }
    }
  }

  infos = get_kb_item( "get_app/" + get_script_oid() + "/port_cpe" );
  if( infos ) {
    _infos = split( infos, sep:'#-#', keep:FALSE );
    ret_arr['cpe']  = _infos[0];
    ret_arr['port'] = _infos[1];
    return ret_arr;
  }

  return;
}

function get_single_app_version_from_list( cpe_list, port ) {

  local_var cpe_list, port, cpe, ap;

  if( ! cpe_list ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe_list#-#get_single_app_version_from_list" );

  foreach cpe( cpe_list )
  {
    ap = get_app_details( cpe:cpe, typ:"version", port:port );
    if( ap )
      return ap;
  }
  return;
}

function get_app_port( cpe, service, all ) {

  local_var cpe, service, all, base_cpe, port, services;

  if( ! cpe ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_app_port" );

  if( typeof( cpe ) == "array" ) {
    if( all )
      return get_all_app_port_from_list( cpe_list:cpe, service:service );
    else
      return get_single_app_port_from_list( cpe_list:cpe, service:service );
  }

  if( ! base_cpe = get_base_cpe( cpe:cpe ) ) {
    set_kb_item( name:"nvt_debug_cpe_syntax/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_app_port" );
    return;
  }

  port = get_kb_item( "get_app/ports/" + base_cpe ); # this could fork
  if( port == "local" ) port = 0; # See function register_product

  if( service ) {
    services = get_kb_item( "get_app/services/" + port + "/" + base_cpe ); # this could fork
    if( port =~ '^[0-9]{1,5}$' && services >< service ) return port;
  } else {
    if( port =~ '^[0-9]{1,5}$' ) return port;
  }
  return;
}

function get_app_version_and_location( cpe, port, exit_no_version, version_regex) {

  local_var cpe, port, exit_no_version, version_regex;

  if( ! cpe ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_app_version_and_location" );
  return get_app_details( cpe:cpe, typ:"version_location", port:port, exit_no_version:exit_no_version , version_regex:version_regex);
}

function get_app_location_and_proto( cpe, port ) {

  local_var cpe, port;

  if( ! cpe ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_app_location_and_proto" );
  return get_app_details( cpe:cpe, typ:"location_proto", port:port );
}

function get_app_version_and_proto( cpe, port, exit_no_version ) {

  local_var cpe, port, exit_no_version;

  if( ! cpe ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_app_version_and_proto" );
  return get_app_details( cpe:cpe, typ:"version_proto", port:port, exit_no_version:exit_no_version );
}

function get_app_full( cpe, port ) {

  local_var cpe, port;

  if( ! cpe ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_app_full" );
  return get_app_details( cpe:cpe, typ:"full", port:port );
}

# get the port from just the prefix.
# For example "cpe:/h:qnap:ts-x53" is the full cpe but we are looking
# for "cpe:/h:qnap" only.
function get_app_port_from_cpe_prefix( cpe )
{
  local_var cpe, port, data, entry, _cpe;

  if( ! cpe ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_app_port_from_cpe_prefix" );
    return;
  }

  data = get_kb_list( "get_app/ports/" + cpe + '*' );
  if( ! data )
    return;

  foreach entry ( keys( data ) )
  {
    if( cpe >!< entry )
      continue;

    parts = split( entry, sep:"/", keep:FALSE );

    if( max_index( parts ) < 4 )
      continue;

    if( parts[2] != 'cpe:' )
      continue;

    _cpe = parts[2] + '/' + parts[3];

    if( cpe >!< _cpe )
      continue;

    return get_app_port( cpe:_cpe );

  }
  return;
}

function get_app_details( cpe, typ, port, exit_no_version, service, nofork, version_regex ) {

  local_var cpe, typ, port, exit_no_version, service, nofork, version_regex;
  local_var base_cpe, version_list, ap, dt, t, t_cpe, app_versions, app_locations;
  local_var t_oid, t_loc, app_details, x, x_oid, x_cpe, x_loc, x_port, x_proto, x_service, ret_arr;

  if( ! base_cpe = get_base_cpe( cpe:cpe ) ) {
    set_kb_item( name:"nvt_debug_cpe_syntax/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_app_details" );
    return;
  }

  # "1.3.6.1.4.1.25623.1.0.xxxxx#-#cpe:/a:foo:bar:1.1.0#-#/foo#-#80" or
  # "1.3.6.1.4.1.25623.1.0.xxxxx#-#cpe:/a:foo:bar:1.1.0#-#/foo#-#80#-#www"
  if( typ == 'all_versions' )
  {
    version_list = make_list();

    ap = get_kb_list( "get_app/" + base_cpe );
    if( ! ap ) return;
    foreach dt ( ap )
    {
      t = split( dt, sep:'#-#', keep:FALSE );
      t_cpe = t[1];

      if( ! t_cpe ) continue;
      if( ! app_versions = get_version_from_cpe( cpe:t_cpe ) ) continue;

      version_list = make_list( version_list, app_versions );
    }

    register_host_detail( name:"detected_by", value:t[0] );
    if( ! isnull( t[2] ) )
      register_host_detail( name:"detected_at", value:t[2] );

    return version_list;

  }
  else if( nofork && typ == 'version' ) # nofork is currently only valid for get_app_version() and get_app_location
  {
    ap = get_kb_list( "get_app/" + base_cpe );
    if( ! ap ) return;
    foreach dt ( ap )
    {
      t = split( dt, sep:'#-#', keep:FALSE );
      t_cpe = t[1];

      if( ! t_cpe ) continue;

      if( ! app_versions = get_version_from_cpe( cpe:t_cpe ) ) continue;

      if( version_regex )
        if( ! ereg( pattern:version_regex, string:app_versions ) ) continue;

      register_host_detail( name:"detected_by", value:t[0] );
      if( ! isnull( t[2] ) )
        register_host_detail( name:"detected_at", value:t[2] );

      return app_versions;
    }
    return; # no version...
  } else if( nofork && typ == 'location' ) { # nofork is currently only valid for get_app_version() and get_app_location
    ap = get_kb_list( "get_app/" + base_cpe );
    if( ! ap ) return;
    app_locations = make_list();
    foreach dt( ap ) {
      t = split( dt, sep:'#-#', keep:FALSE );
      t_oid = t[0];
      t_loc = t[2];
      if( isnull( t_oid ) && isnull( t_loc ) ) continue;

      register_host_detail( name:"detected_by", value:t_oid );
      if( ! isnull( t[2] ) )
        register_host_detail( name:"detected_at", value:t_loc );

      app_locations = make_list( app_locations, t_loc );
    }
    return app_locations;
  }
  else
    app_details = get_kb_item( "get_app/" + base_cpe ); # this could fork

  if( ! app_details ) return;

  x = split( app_details, sep:'#-#', keep:FALSE );

  x_oid       = x[0];
  x_cpe       = x[1];
  x_loc       = x[2];
  x_port      = x[3];
  x_proto     = x[4];
  if( x[5] )
    x_service = x[5];

  if( service )
    if( x_service != service ) return;

  if( ! isnull( port ) )
    if( int( x_port ) != int( port ) ) return;

  if( typ == 'version' )
  {
    if( ! app_versions = get_version_from_cpe( cpe:x_cpe ) ) return;

    if( version_regex )
      if( ! ereg( pattern:version_regex, string:app_versions ) ) return;

    register_host_detail( name:"detected_by", value:x_oid );
    if( x_loc ) register_host_detail( name:"detected_at", value:x_loc );

    return app_versions;
  }

  if( typ == 'location' )
  {
    if( x_loc )
    {
      register_host_detail( name:"detected_by", value:x_oid );
      if( x_loc ) register_host_detail( name:"detected_at", value:x_loc );

      return x_loc;
    }
    return;
  }

  if( typ == 'version_location' )
  {
    app_versions = get_version_from_cpe( cpe:x_cpe );

    if( ! app_versions && exit_no_version == TRUE ) exit( 0 );
    if( ! app_versions && ! x_loc ) return;

    if( app_versions )
    {
      if( version_regex )
        if( ! ereg( pattern:version_regex, string:app_versions ) ) return;

      ret_arr['version'] = app_versions;
    }  
    else
      ret_arr['version'] = '';

    if( x_loc )
      ret_arr['location'] = x_loc;
    else
      ret_arr['location'] = '';

    register_host_detail( name:"detected_by", value:x_oid );
    if( x_loc ) register_host_detail( name:"detected_at", value:x_loc );

    return ret_arr;
  }

  if( typ == 'version_proto' )
  {
    app_versions = get_version_from_cpe( cpe:x_cpe );

    if( ! app_versions && exit_no_version == TRUE ) exit( 0 );
    if( ! app_versions && ! x_proto ) return;

    if( app_versions )
      ret_arr['version'] = app_versions;
    else
      ret_arr['version'] = '';

    if( x_proto )
      ret_arr['proto'] = x_proto;
    else
       ret_arr['proto'] = 'tcp';

    register_host_detail( name:"detected_by", value:x_oid );
    if( x_proto && x_port ) register_host_detail( name:"detected_at", value: x_port + "/" + x_proto );

    return ret_arr;
  }

  if( typ == 'location_proto' )
  {

    if( x_proto )
      ret_arr['proto'] = x_proto;
    else
      ret_arr['proto'] = 'tcp';

    if( x_loc )
      ret_arr['location'] = x_loc;
    else
      ret_arr['location'] = '';

    register_host_detail( name:"detected_by", value:x_oid );
    if( x_loc ) register_host_detail( name:"detected_at", value:x_loc );

    return ret_arr;
  }

  if( typ == 'full' )
  {
    app_versions = get_version_from_cpe( cpe:x_cpe );

    ret_arr['version']     = app_versions;
    ret_arr['location']    = x_loc;
    ret_arr['full_cpe']    = x_cpe;
    ret_arr['port']        = x_port;
    ret_arr['proto']       = x_proto;
    if( x_service )
      ret_arr['service']   = x_service;
    ret_arr['detected_by'] = x_oid;

    register_host_detail( name:"detected_by", value:x_oid );
    if( x_loc ) register_host_detail( name:"detected_at", value:x_loc );

    return ret_arr;
  }

  return;

}

function get_version_from_cpe( cpe ) {

  local_var cpe, token_val, tokens, app_versions;

  if( isnull ( cpe ) ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpe#-#get_version_from_cpe" );
    return;
  }

  tokens = split( cpe, sep:":", keep:FALSE );

  # Possible CPEs are e.g.
  # cpe:/a:extplorer:extplorer:2.1.0:RC5
  # cpe:/o:canonical:ubuntu_linux:12.04:-:lts
  # cpe:/o:microsoft:windows_7:::x64
  # nb: Some are also setting a CPE with a wrong syntax like cpe:/a:vendor:product:x64:1.1
  # which should be cpe:/a:vendor:product:1.1::x64

  # Test-cases:
  # CPE: cpe:/a:foo0:bar0:x64:1.2.3 , expected version: 1.2.3, returned version: 1.2.3
  # CPE: cpe:/a:foo1:bar1:x64:1.2.3:RC1 , expected version: 1.2.3RC1 , returned version: 1.2.3RC1
  # CPE: cpe:/a:foo2:bar2:1.2.3 , expected version: 1.2.3, returned version: 1.2.3
  # CPE: cpe:/a:foo3:bar3:1.2.3:RC2 , expected version: 1.2.3RC2, returned version: 1.2.3RC2
  # CPE: cpe:/a:foo4:bar4:1.2.3:RC3:x64 , expected version: 1.2.3RC3, returned version: 1.2.3RC3
  # CPE: cpe:/a:foo5:bar5:1.2.3:RC4:x32 , expected version: 1.2.3RC4, returned version: 1.2.3RC4
  # CPE: cpe:/a:foo6:bar6:1.2.3:-:x64 , expected version: 1.2.3, returned version: 1.2.3
  # CPE: cpe:/a:foo7:bar7:1.2.3:-:x32 , expected version: 1.2.3, returned version: 1.2.3
  # CPE: cpe:/a:foo8:bar8:1.2.3::x64 , expected version: 1.2.3, returned version: 1.2.3
  # CPE: cpe:/a:foo9:bar9:1.2.3::x32 , expected version: 1.2.3, returned version: 1.2.3
  # CPE: cpe:/a:foo10:bar10:-:-:x64 , expected version: NULL, returned version:
  # CPE: cpe:/a:foo11:bar11:-:-:x32 , expected version: NULL, returned version:
  # CPE: cpe:/a:foo12:bar12:::x64 , expected version: NULL, returned version:
  # CPE: cpe:/a:foo13:bar13:::x32 , expected version: NULL, returned version:
  # CPE: cpe:/a:foo14:bar14::sp2:x64 , expected version: sp2, returned version: sp2
  # CPE: cpe:/a:foo15:bar15::sp2:x32 , expected version: sp2, returned version: sp2
  # CPE: cpe:/a:foo16:bar16:-:sp2:x64 , expected version: sp2, returned version: sp2
  # CPE: cpe:/a:foo17:bar17:-:sp2:x32 , expected version: sp2, returned version: sp2

  if( ! isnull( tokens[4] ) ) {

    # catch the wrong CPE syntax cpe:/a:foo0:bar0:x64:1.2.3 described above
    if( tokens[4] == "x64" )
      token_val = 1;
    else
      token_val = 0;

    # handle cpe:/a:foo3:bar3:1.2.3:RC2
    if( ! isnull( tokens[5 + token_val] ) &&
        tokens[5 + token_val] != "-" && tokens[5 + token_val] != "" ) {

      if( tokens[4 + token_val] != "-" && tokens[4 + token_val] != "" )
        app_versions = tokens[4 + token_val] + "" + tokens[5 + token_val]; # handle cpe:/a:foo3:bar3:1.2.3:RC2
      else
        app_versions = tokens[5 + token_val]; # handle cpe:/a:foo10:bar10:-:sp2

    } else {
      # handle cpe:/a:foo2:bar2:1.2.3
      if( tokens[4 + token_val] != "-" && tokens[4 + token_val] != "" )
        app_versions = tokens[4 + token_val];
    }
  }

  if( ! app_versions ) return;

  return app_versions;
}

function get_base_cpe( cpe ) {

  local_var cpe, base_cpe, bc;

  if( ! cpe ) return;

  bc = split( cpe, sep:':', keep:FALSE );
  if( ! bc || max_index( bc ) < 4 ) return;

  if( bc[0] != 'cpe' || bc[1] !~ '/(a|o|h)$' ) return;

  base_cpe = bc[0] + ':' + bc[1] + ':' + bc[2] + ':' + bc[3];

  return base_cpe;
}

function build_detection_report( app, version, install, regpath, cpe, concluded, concludedUrl, extra, skip_version ) {

  local_var app, version, install, regpath, cpe, concluded, concludedUrl, extra, skip_version, report;

  if( isnull( app ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#app#-#build_detection_report" );

  report = 'Detected ' + app + '\n';

  if( ! skip_version ) {
    if( ! version ) version = 'unknown';
    report += '\nVersion:  ' + version;
  }

  report += '\nLocation: ' + install;

  if( strlen( cpe ) > 0 ) {
    report += '\nCPE:      '+ cpe;
  }

  if( strlen( regpath ) > 0 ) {
    report += '\nRegistry path: '+ regpath;
  }

  if( strlen( concluded ) > 0 && tolower( concluded ) != "unknown" ) {
    report += '\n\nConcluded from version/product identification result:\n' + concluded;
  }

  if( strlen( concludedUrl ) > 0 ) {
    report += '\n\nConcluded from version/product identification location:\n' + concludedUrl;
  }

  if( strlen( extra ) > 0 ) {
    report += '\n\nExtra information:\n' + extra;
  }

  return report;
}

function register_and_report_os( os, version, cpe, banner_type, port, proto, banner, desc, runs_key ) {

  local_var os, version, cpe, banner_type, port, proto, banner, report, desc, runs_key;

  oid = get_script_oid();
  if( ! proto ) proto = "tcp";

  if( ! desc ) set_kb_item( name: "nvt_debug_empty/" + oid, value:oid + "#-#desc#-#register_and_report_os" );

  if( version ) {
    if( cpe ) cpe += ":" + version;
    if( os ) os += " " + version;
  }

  if( cpe ) {
    register_host_detail( name:"OS", value:cpe, desc:desc );
  } else {
    cpe = "N/A";
  }

  if( os ) {
    register_host_detail( name:"OS", value:os, desc:desc );
  } else {
    os = "N/A";
  }

  report = 'OS: ' + os;

  if( version )
    report += '\nVersion: ' + version;

  report += '\nCPE: ' + cpe;
  report += '\nFound by NVT: ' + oid + ' (' + desc + ')';

  if( banner_type ) {

    report += '\nConcluded from ' + banner_type;

    if( port && proto != "icmp" )
      report += " on port " + port + "/" + proto;

    if( banner ) {
      banner = chomp( banner ); # Few banners have newlines at the end so removing these here
      report += ': ' + banner;
    }
  }

  # Keep down here as we only need this defaults for the set_kb_item
  if( ! port ) port = "0";
  set_kb_item( name:"os_detection_report/reports/" + oid + "/" + port + "/" + proto, value:report );

  # For setting the "Host/runs_windows" or "Host/runs_unixoide" key in os_detection.nasl
  if( ! isnull( runs_key ) ) {
    set_kb_item( name:"os_detection_report/host_runs/" + oid + "/" + port + "/" + proto, value:runs_key );
  } else {
    set_kb_item( name:"os_detection_report/host_runs/" + oid + "/" + port + "/" + proto, value:"unknown" );
  }
}

function register_unknown_os_banner( banner, banner_type_name, banner_type_short, port, proto ) {

  local_var banner, banner_type_name, banner_type_short, port, proto;

  oid = get_script_oid();

  if( ! banner ) {
    set_kb_item( name:"nvt_debug_empty/" + oid, value:oid + "#-#banner#-#register_unknown_os_banner" );
    return;
  }

  if( ! banner_type_name ) {
    set_kb_item( name:"nvt_debug_empty/" + oid, value:oid + "#-#banner_type_name#-#register_unknown_os_banner" );
    return;
  }

  if( ! banner_type_short ) {
    set_kb_item( name:"nvt_debug_empty/" + oid, value:oid + "#-#banner_type_short#-#register_unknown_os_banner" );
    return;
  }

  banner = chomp( banner ); # Few banners have newlines at the end so removing these here

  # Don't report known banner were we know that it doesn't contain info about an OS here
  if( banner == '* ID ("name" "Dovecot")' ||
      banner == "+OK Dovecot ready." ||
      banner == "220 Welcome message" || # Default welcome messages on some FTP servers
      banner == "220 Service ready for new user." || # Default welcome messages on some FTP servers
      banner == "Server:" ||
      banner == "Server: " ||
      banner == "Server: Undefined" || # Unknown
      banner == "Server: squid" ||
      banner == "Server: nginx" ||
      banner == "Server: Apache" ||
      banner == "Server: lighttpd" ||
      banner == "Server: sfcHttpd" ||
      banner == "Server: Allegro-Software-RomPager" || # Vendor: "Works with any OS vendor and will function without an OS if needed"
      banner == "SSH-2.0-RomSShell" || # Vendor: "Works with any OS vendor and will function without an OS if needed"
      banner == "SSH-2.0-OpenSSH" ||
      banner == "SSH-2.0-OpenSSH_" ||
      banner == "Server: Apache-Coyote/1.0" ||
      banner == "Server: Apache-Coyote/1.1" ||
      banner == "Server: HASP LM" || # Is running under windows and linux
      banner == "Server: Mbedthis-Appweb" || # Is running under various OS variants
      banner == "Server: Embedthis-Appweb" || # Is running under various OS variants
      banner == "Server: Embedthis-http" || # Is running under various OS variants
      banner == "Server: GoAhead-Webs" || # Is running under various OS variants
      banner == "Server: Mojolicious (Perl)" || # Cross-platform
      banner == "Server: Java/0.0" || # Cross-platform, running on e.g. VIBNODE devices
      banner == "+OK POP3 ready" ||
      banner == "+OK POP3" ||
      banner == "* OK IMAPrev1" ||
      banner == "220 FTP server ready" ||
      banner == "220 FTP server ready." ||
      banner == "Server: NessusWWW" || # Nessus could be running on Windows, Linux/Unix or MacOS
      banner == "X-Powered-By: Express" || # Express Framework is supported on Windows, Linux/Unix etc.
      banner == "Server: Embedded Web Server" ||
      banner == "SSH-2.0-Mocana SSH" || # Cross-platform
      banner == "login:" ||
      "500 OOPS: could not bind listening IPv4 socket" >< banner || # Some broken FTP server
      "erver: BBC " >< banner || # OV Communication Broker runs on various different OS variants
      "Server: PanWeb Server/" >< banner || # Already covered by gb_palo_alto_webgui_detect.nasl
      " FTP server (MikroTik " >< banner || # Already covered by gb_mikrotik_router_routeros_consolidation.nasl
      egrep( pattern:"^Server: DHost/([0-9.]+) HttpStk/([0-9.]+)$", string:banner ) || # DHost/9.0 HttpStk/1.0 from Novell / NetIQ eDirectory, runs on various OS variants
      egrep( pattern:"^MikroTik ", string:banner ) || # Already covered by gb_mikrotik_router_routeros_consolidation.nasl
      egrep( pattern:"^OS String: Unix; SMB String: Samba ([0-9.]+)(a|b|c)?$", string:banner ) || # e.g. OS String: Unix; SMB String: Samba 4.0.9 set by smb_nativelanman.nasl
      egrep( pattern:"^220 ([0-9a-zA-Z._\-]+) ESMTP( Postfix)?$", string:banner ) || # e.g. 220 hostname ESMTP or 220 mail.example.com ESMTP Postfix
      egrep( pattern:"ESMTP Exim ([0-9._]+) ", string:banner ) || # e.g. 220 host ESMTP Exim 4.84_2 Tue, 01 Aug 2017 13:01:18 +0200
      egrep( pattern:"^X-Powered-By: PHP/([0-9.]+)(-[0-9]+)?$", string:banner ) || # e.g. X-Powered-By: PHP/7.0.19 or X-Powered-By: PHP/7.0.19-1
      egrep( pattern:"^Server: CUPS/([0-9.]+) IPP/([0-9.]+)$", string:banner ) || # Handled at the bottom of sw_http_os_detection.nasl
      egrep( pattern:"^Server: CUPS/([0-9.]+)$", string:banner ) || # Handled at the bottom of sw_http_os_detection.nasl
      egrep( pattern:"^Server: Tomcat/([0-9.]+)$", string:banner ) || # Quite outdated Tomcat, e.g. Server: Tomcat/2.1
      egrep( pattern:"^Server: Themis ([0-9.]+)$", string:banner ) || # Currently unknown
      egrep( pattern:"^Server: Mordac/([0-9.]+)$", string:banner ) || # Currently unknown
      egrep( pattern:"^Server: eHTTP v([0-9.]+)$", string:banner ) || # Currently unknown, have seen this on HP ProCurves but also on some login pages without any info
      egrep( pattern:"^Server: Agranat-EmWeb/([0-9_R]+)$" ) || # Currently unknown, might be an Alcatel device...
      egrep( pattern:"^Server: gSOAP/([0-9.]+)$", string:banner ) || # Cross-platform
      egrep( pattern:"^Server: squid/([0-9.]+)$", string:banner ) ||
      egrep( pattern:"^Server: squid/([0-9.]+)\.STABLE([0-9.]+)$", string:banner ) || # e.g. Server: squid/2.7.STABLE5
      egrep( pattern:"^Server: Jetty\(([0-9.v]+\))$", string:banner ) || # e.g. Server: Jetty(7.3.1.v20110307)
      egrep( pattern:"^Server: nginx/([0-9.]+)$", string:banner ) ||
      egrep( pattern:"^Server: Apache/([0-9.]+)$", string:banner ) ||
      egrep( pattern:"^Server: lighttpd/([0-9.]+)$", string:banner ) ||
      egrep( pattern:"^Server: CompaqHTTPServer/([0-9.]+)$", string:banner ) || # HP SMH, cross-platform, e.g. Server: CompaqHTTPServer/2.1
      egrep( pattern:"^Server: http server ([0-9.]+)$", string:banner ) || # e.g. Server: http server 1.0
      egrep( pattern:"^Server: Web Server ([0-9.]+)$", string:banner ) || # e.g. Server: Web Server 1.1
      egrep( pattern:"^Server: MiniServ/([0-9.]+)$", string:banner ) || # From Webmin/Usermin, cross-platform,  e.g. Server: MiniServ/1.550
      egrep( pattern:"^Server: RealVNC/([0-9.]+)$", string:banner ) || # Cross-platform, e.g. Server: RealVNC/4.0
      egrep( pattern:"^Server: HASP LM/([0-9.]+)$", string:banner ) || # Is running under windows and linux
      egrep( pattern:"^Server: Mbedthis-Appweb/([0-9.]+)$", string:banner ) || # Is running under various OS variants
      egrep( pattern:"^Server: Embedthis-http/([0-9.]+)$", string:banner ) || # Is running under various OS variants, banner e.g. Server: Embedthis-http/4.0.0
      egrep( pattern:"^Server: Embedthis-Appweb/([0-9.]+)$", string:banner ) || # Is running under various OS variants
      egrep( pattern:"^Server: GoAhead-Webs/([0-9.]+)$", string:banner ) || # Is running under various OS variants
      egrep( pattern:"^Server: Allegro-Software-RomPager/([0-9.]+)$", string:banner ) || # Vendor: "Works with any OS vendor and will function without an OS if needed"
      egrep( pattern:"^Server: CompaqHTTPServer/([0-9.]+) HPE System Management Homepage$", string:banner ) || # Is running under various OS variants
      egrep( pattern:"^Server: CompaqHTTPServer/([0-9.]+) HP System Management Homepage/([0-9.]+)$", string:banner ) || # e.g. Server: CompaqHTTPServer/9.9 HP System Management Homepage/2.1.2.127, is running under various OS variants
      egrep( pattern:"^Server: Payara Server  ([0-9.]+) #badassfish$", string:banner ) || # Cross-platform, e.g. Server: Payara Server  4.1.2.172 #badassfish
      egrep( pattern:"^SSH-2\.0-RomSShell_([0-9.]+)$", string:banner ) || # Vendor: "Works with any OS vendor and will function without an OS if needed"
      egrep( pattern:"^([0-9.]+)$", string:banner ) || # Bind9 and MySQL. Both are often only sending e.g. 9.4.2
      egrep( pattern:"^([0-9.]+)(-[0-9.]+)?-(MariaDB|log)$", string:banner ) || # MariaDB, e.g. 5.5.5-10.1.19-MariaDB or 5.5.49-MariaDB, MySQL e.g. 5.5.54-38.6-log or 5.6.25-log
      egrep( pattern:"^SSH-2\.0-Mocana SSH ([0-9.]+)$", string:banner ) || # platform independent
      egrep( pattern:"^SSH-1\.99-OpenSSH_([0-9.p]+)$", string:banner ) ||
      egrep( pattern:"^SSH-2\.0-OpenSSH_([0-9.p]+)-FIPS_hpn([0-9v]+)$", string:banner ) || # SSH-2.0-OpenSSH_6.1-FIPS_hpn13v11
      egrep( pattern:"^SSH-2\.0-OpenSSH_([0-9.p]+)(\-FIPS\(capable\))?$", string:banner ) ) {

    return;
  }

  if( ! proto ) proto = "tcp";
  if( ! port )  port  = "0";

  set_kb_item( name:"os_detection_report/unknown_os_banner/" + oid + "/" + port + "/" + proto + "/" + banner_type_short + "/banner", value:banner );
  set_kb_item( name:"os_detection_report/unknown_os_banner/" + oid + "/" + port + "/" + proto + "/" + banner_type_short + "/type_full", value:banner_type_name );
  set_kb_item( name:"unknown_os_or_service/available", value:TRUE ); # Used in gb_unknown_os_service_reporting.nasl
}
