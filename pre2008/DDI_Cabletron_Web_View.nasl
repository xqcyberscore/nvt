# OpenVAS Vulnerability Test
# $Id: DDI_Cabletron_Web_View.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Cabletron Web View Administrative Access
#
# Authors:
# Forrest Rae
#
# Copyright:
# Copyright (C) 2002 Digital Defense Incorporated
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

tag_summary = "This host is a Cabletron switch and is running
Cabletron WebView. This web software
provides a graphical, real-time representation of
the front panel on the switch. This graphic,
along with additionally defined areas of the
browser interface, allow you to interactively
configure the switch, monitor its status, and
view statistical information. An attacker can
use this to gain information about this host.";

tag_solution = "Depending on the location of the switch, it might
be advisable to restrict access to the web server by IP 
address or disable the web server completely.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10962");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 name = "Cabletron Web View Administrative Access";
 script_name(name);

 	summary = "Cabletron Web View Administrative Access";
	script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
	script_copyright("This script is Copyright (C) 2002 Digital Defense Incorporated");
	family = "Privilege escalation";
	script_family(family);
	script_dependencies("find_service.nasl");
    script_require_ports("Services/www");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
	exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{
	soc = http_open_socket(port);
	if(soc)
	{
		req = http_get(item:string("/chassis/config/GeneralChassisConfig.html"), port:port);
		send(socket:soc, data:req);
		
		r = http_recv(socket:soc);
		     
		if("Chassis Configuration" >< r)
		{
			security_message(port:port); 
			set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
			exit(0);
		}

		http_close_socket(soc);
	}
}



