# OpenVAS Vulnerability Test
# $Id: visualroute_server_detect.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: VisualRoute Web Server Detection
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

tag_summary = "We detected the remote web server as being a VisualRoute web server. 
This server allows attackers to perform a traceroute to a third party's 
hosts without revealing themselves to the target of the traceroute.";

tag_solution = "Disable the VisualRoute web server, or block the web server's
port number on your Firewall.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10744");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 name = "VisualRoute Web Server Detection";
 script_name(name);
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");

 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 family = "General";
 script_family(family);

 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("VisualRoute/banner");
 script_require_ports("Services/www", 8000);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
 
port = get_http_port( default:8000 );

  banner = get_http_banner(port:port);
  if(!banner)exit(0);


  if (egrep(pattern:"^Server: VisualRoute (tm) ", string:banner))
  {
   security_message(port);
  }


