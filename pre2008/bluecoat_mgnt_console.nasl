# OpenVAS Vulnerability Test
# $Id: bluecoat_mgnt_console.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: BlueCoat ProxySG console management detection
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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

tag_summary = "The remote host appears to be a BlueCoat ProxySG, connections are
allowed to the web console management.

Letting attackers know that you are using a BlueCoat will help them to 
focus their attack or will make them change their strategy.";

tag_solution = "Filter incoming traffic to this port";

#  thanks to the help of rd

if(description)
{
 script_id(16363);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 
 name = "BlueCoat ProxySG console management detection";

 script_name(name);
 

 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 
 family = "Firewalls";
 script_family(family);
 script_dependencies("http_version.nasl");

 script_require_ports(8082);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = 8082;
if(get_port_state(port))
{
  req = http_send_recv(data:http_get(item:"/Secure/Local/console/logout.htm", port:port), port:port);
  if("<title>Blue Coat Systems  - Logout</title>" >< req)
  {
    security_message(port);
  }
}
