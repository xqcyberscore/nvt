# OpenVAS Vulnerability Test
# $Id: checkpoint_open_web_admin.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Checkpoint Firewall open Web administration
#
# Authors:
# Matthew North < matthewnorth@yahoo.com >
# Changes by rd: Description and usage of the http_func functions.
#
# Copyright:
# Copyright (C) 2003 Matthew North
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

tag_summary = "The remote Checkpoint Firewall is open to Web administration.

An attacker use it to launch a brute force password attack
against the firewall, and eventually take control of it.";

tag_solution = "Disable remote Web administration or filter packets going to this port";

# Checks to see if remote Checkpoint Firewall is open to Web administration.
# If it is open to web administration, then a brute force password attack 
# against the Firewall can be launch.

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11518");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
 name = "Checkpoint Firewall open Web administration";
 script_name(name);
 



 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_probe");
 
 script_copyright("This script is Copyright (C) 2003 Matthew North");
 family = "Firewalls";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
res = http_get_cache(port:port, item:"/");
if (res != NULL ) {
    if("ConfigToolPassword" >< res) {
           security_message(port);
    }
}
