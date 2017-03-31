###############################################################################
# OpenVAS Vulnerability Test
# $Id: host_details.nasl 5475 2017-03-03 08:56:55Z cfi $
#
# Host Details
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103997");
  script_version("$Revision: 5475 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-03 09:56:55 +0100 (Fri, 03 Mar 2017) $");
  script_tag(name:"creation_date", value:"2011-03-16 12:21:12 +0100 (Wed, 16 Mar 2011)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Host Details");
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Service detection");
  script_category(ACT_END);
  script_dependencies("gb_wmi_get-dns_name.nasl", "gb_nist_win_oval_sys_char_generator.nasl",
                      "host_scan_end.nasl", "gb_tls_version.nasl", "find_service_nmap.nasl");

  script_tag(name:"summary", value:"This scripts aggregates the OS detection information gathered by several
  NVTs and store it in a structured and unified way.");

  script_tag(name:"qod_type", value:"remote_probe");

  exit(0);
}

SCRIPT_DESC = "Host Details";

include("host_details.inc");

hostname = get_host_name();
if( !isnull( hostname ) && hostname != '' && hostname != get_host_ip() ) {
  register_host_detail( name:"hostname", value:hostname, desc:SCRIPT_DESC );
  register_host_detail( name:"DNS-via-TargetDefinition", value:hostname, desc:SCRIPT_DESC );
}

if( hostname == get_host_ip() || hostname == "" || isnull( hostname ) ) {
  DNS_via_WMI_FQDNS = get_kb_item( "DNS-via-WMI-FQDNS" );
  if( ! isnull( DNS_via_WMI_FQDNS ) && DNS_via_WMI_FQDNS != '' && DNS_via_WMI_FQDNS != get_host_ip() ) {
    register_host_detail( name:"hostname", value:DNS_via_WMI_FQDNS, desc:SCRIPT_DESC );
  } else {
    DNS_via_WMI_DNS = get_kb_item( "DNS-via-WMI-DNS" );
    if( ! isnull( DNS_via_WMI_DNS ) && DNS_via_WMI_DNS != '' && DNS_via_WMI_DNS != get_host_ip() ) {
      register_host_detail( name:"hostname", value:DNS_via_WMI_DNS, desc:SCRIPT_DESC );
    } else {
      SMB_HOST_NAME = get_kb_item( "SMB/name" );
      if( ! isnull( SMB_HOST_NAME ) && SMB_HOST_NAME != '' && SMB_HOST_NAME != get_host_ip() ) {
        register_host_detail( name:"hostname", value:SMB_HOST_NAME, desc:SCRIPT_DESC );
      }
    }
  }
}

report_host_details = get_preference( "report_host_details" );
if( report_host_details && "yes" >< report_host_details ) {
  report_host_details();
}

exit( 0 );