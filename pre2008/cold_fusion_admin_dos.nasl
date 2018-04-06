# OpenVAS Vulnerability Test
# $Id: cold_fusion_admin_dos.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Cold Fusion Administration Page Overflow
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
# Update - 13.9.01 - Felix Huber <huberfelix@webtopia.de>
#
# Copyright:
# Copyright (C) 2000 Matt Moore
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

tag_summary = "A denial of service vulnerability exists within the Allaire
ColdFusion web application server (version 4.5.1 and earlier) which allows an 
attacker to overwhelm the web server and deny legitimate web page requests.

By downloading and altering the login HTML form an attacker can send overly 
large passwords (>40,0000 chars) to the server, causing it to stop responding.";

tag_solution = "Use HTTP basic authentication to restrict access to this page or
remove it entirely if remote administration is not a requirement. 
A patch should be available from allaire - www.allaire.com..";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10581");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1314);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2000-0538");
 name = "Cold Fusion Administration Page Overflow";
 script_name(name);
 



 
 
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 
 
 script_copyright("This script is Copyright (C) 2000 Matt Moore");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{ 
 # CFIDE will work with CF Linux also
 req = http_get(item:"/CFIDE/administrator/index.cfm",
 		port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if("PasswordProvided" >< r && "cf50" >!< r)	
 	security_message(port);

}
