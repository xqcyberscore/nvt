###############################################################################
# OpenVAS Vulnerability Test
# $Id: websense_detect.nasl 8869 2018-02-19 14:09:59Z cfischer $
#
# Websense reporting console detection
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18177");
  script_version("$Revision: 8869 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-19 15:09:59 +0100 (Mon, 19 Feb 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Websense reporting console detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Service detection");
  # nb: Don't add a dependency to http_version.nasl or gb_get_http_banner.nasl to avoid cyclic dependency to embedded_web_server_detect.nasl
  script_dependencies("find_service.nasl", "httpver.nasl");
  script_require_ports("Services/www", 8010);
  script_exclude_keys("Settings/disable_cgi_scanning");

  tag_summary = "The remote host appears to be running Websense, connections are allowed 
  to the web reporting console.

  Letting attackers know that you are using this software will help them 
  to focus their attack or will make them change their strategy.";

  tag_solution = "Filter incoming traffic to this port";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:8010 );

url = "/Websense/cgi-bin/WsCgiLogin.exe";
req = http_get( item:url, port:port );
rep = http_keepalive_send_recv( port:port, data:req );
if( rep == NULL ) exit( 0 );

if( "<title>Websense Enterprise - Log On</title>" >< rep ) {
  security_message( port:port );
  set_kb_item( name:"Services/www/" + port + "/embedded", value:TRUE );
}

exit( 0 );
