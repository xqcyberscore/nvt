# OpenVAS Vulnerability Test
# $Id: oracle9i_dad_admin.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Oracle 9iAS DAD Admin interface
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added link to the Bugtraq message archive
#
# Copyright:
# Copyright (C) 2002 Matt Moore
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

tag_summary = "In a default installation of Oracle 9iAS, it is possible to access the 
mod_plsql DAD Admin interface. Access to these pages should be restricted.";

tag_solution = "Edit the wdbsvr.app file, and change the setting 'administrators=' to 
named users who are allowed admin privileges.

Reference : http://online.securityfocus.com/archive/1/155881";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10849");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 name = "Oracle 9iAS DAD Admin interface";
 script_name(name);
 

 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
 
 script_copyright("This script is Copyright (C) 2002 Matt Moore");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

# Check starts here

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{ 
# Make a request for the Admin_ interface.
 req = http_get(item:"/pls/portal30/admin_/", port:port);	      
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("Gateway Configuration Menu" >< r)	
 	security_message(port);

 }
}
