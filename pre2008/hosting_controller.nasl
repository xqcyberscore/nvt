# OpenVAS Vulnerability Test
# $Id: hosting_controller.nasl 3362 2016-05-20 11:19:10Z antu123 $
# Description: Hosting Controller vulnerable ASP pages
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

tag_summary = "The Hosting Controller application resides on this server.  
This version is vulnerable to multiple remote exploits.  

At attacker may make use of this vulnerability and use it to
gain access to confidential data and/or escalate their privileges
on the Web server.

See http://archives.neohapsis.com/archives/bugtraq/2002-01/0039.html
for more information.";

tag_solution = "remove or update the software.";

if(description)
{
 script_id(11745);
 script_version("$Revision: 3362 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-20 13:19:10 +0200 (Fri, 20 May 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3808);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_cve_id("CVE-2002-0466");
 
 name = "Hosting Controller vulnerable ASP pages";
 script_name(name);
 


 summary = "Checks for the vulnerable instances of Hosting Controller";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_active"); 
 
 
 script_copyright("This script is Copyright (C) 2003 John Lampe");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
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
if ( ! can_host_asp(port:port) ) exit(0);

flag = 0;
directory = "";

file[0] = "statsbrowse.asp";
file[1] = "servubrowse.asp";
file[2] = "browsedisk.asp";
file[3] = "browsewebalizerexe.asp";
file[4] = "sqlbrowse.asp";

for (i=0; file[i]; i = i + 1) {
	foreach dir (cgi_dirs()) {
   		if(is_cgi_installed_ka(item:string(dir, "/", file[i]), port:port)) {
			req = http_get(item:dir + "/" + file[i] + "?filepath=c:" + raw_string(0x5C,0x26) + "Opt=3", port:port);
			res = http_keepalive_send_recv(port:port, data:req);
			if(res == NULL) exit(0);
		       if ( (egrep(pattern:".*\.BAT.*", string:res)) || (egrep(pattern:".*\.ini.*", string:res)) ) {
					security_message(port);
					exit(0);
				}
			}
   		}
	}
