###############################################################################
# OpenVAS Vulnerability Test
# $Id: cobalt_web_admin_server.nasl 6040 2017-04-27 09:02:38Z teissa $
#
# Cobalt Web Administration Server Detection
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 SecuriTeam
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10793");
  script_version("$Revision: 6040 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-27 11:02:38 +0200 (Thu, 27 Apr 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Cobalt Web Administration Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 SecuriTeam");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 81);
  script_exclude_keys("Settings/disable_cgi_scanning");

  tag_summary = "The remote web server is the Cobalt Administration web server.";

  tag_impact = "This web server enables attackers to configure your Cobalt server
  if they gain access to a valid authentication username and password.";

  tag_solution = "Disable the Cobalt Administration web server if
  you do not use it, or block inbound connections to this port.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:81 );

url = "/admin";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

if( "401 Authorization Required" >< res && ( ( "CobaltServer" >< res ) || ( "CobaltRQ" >< res ) ) && ( "WWW-Authenticate: Basic realm=" >< res ) ) {
  set_kb_item( name:"Services/www/" + port + "/embedded", value:TRUE );
  report = report_vuln_url( port:port, url:url );
  log_message( port:port, data:report);
  exit( 0 );
}

exit( 99 );
