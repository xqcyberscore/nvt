# OpenVAS Vulnerability Test
# $Id: eMuleWebServer_detect.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: eMule Plus Web Server detection
#
# Authors:
# A.Kaverin
#
# Copyright:
# Copyright (C) 2004 A.Kaverin
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

tag_summary = "eMule Web Server works on this port. Some versions of this P2P client 
are vulnerable to a DecodeBase16 buffer overflow which would allow an 
attacker to execute arbitrary code.

Thanks to Kostya Kortchinsky for his posting to bugtraq.

Known Vulnerable clients:
eMule 0.42a-d
eMule 0.30e
eMulePlus <1k


* Note: This script only checks if port 4711 is open and if 
it reports banner which contains string eMule. *";

tag_solution = "disable eMule Web Server or upgrade to a bug-fixed version
(eMule 0.42e, eMulePlus 1k or later)";

# This script only checks if port 4711 is open and if it reports banner which contains string "eMule".
# Usually this port is used for Web Server by eMule client and eMulePlus (P2P software).
# This script has been tested on eMule 0.30e; 0.42 c,d,e,g; eMulePlus v.1 i,j,k.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12233");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1892");
  script_bugtraq_id(10039);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("eMule Plus Web Server detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2004 A.Kaverin"); 
  script_family("Peer-To-Peer File Sharing");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("eMule/banner");
  script_require_ports(4711);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://security.nnov.ru/search/news.asp?binid=3572");
  exit(0);
}

include("http_func.inc"); 

port = 4711;
if(! get_port_state(port)) exit(0);
banner = get_http_banner(port:port);
if ( banner && "eMule" >< banner ) {
  security_message(port:port);
}

exit(0);
