# OpenVAS Vulnerability Test
# $Id: oracle_one_hour_install.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Oracle Applications One-Hour Install Detect
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 Noam Rathaus <noamr@securiteam.com>
# Copyright (C) 2001 SecuriTeam
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

tag_summary = "We detected the remote web server as an Oracle 
Applications' One-Hour Install web server. This web server enables
attackers to configure your Oracle Application server and Oracle Database 
server without any need for authentication.";

tag_solution = "Disable the Oracle Applications' One-Hour Install web server
after you have completed the configuration, or block the web server's 
port on your Firewall.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10737");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 name = "Oracle Applications One-Hour Install Detect";
 script_name(name);


 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");

 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 family = "General";
 script_family(family);

 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("oaohi/banner");
 script_require_ports("Services/www", 8002);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
 
port = get_http_port(default:8002);
if (!port) exit(0);


banner = get_http_banner(port:port);
if ( !  banner ) exit(0);

if ("Oracle Applications One-Hour Install" >< banner)
   security_message(port);
