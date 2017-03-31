###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_messaging_gateway_http_detect.nasl 3331 2016-05-17 15:30:33Z mime $
#
# Symantec Messaging Gateway Detection (HTTP)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105720");
  script_version("$Revision: 3331 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-05-17 17:30:33 +0200 (Tue, 17 May 2016) $");
  script_tag(name:"creation_date", value:"2012-12-03 10:06:00 +0100 (Mon, 03 Dec 2012)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Symantec Messaging Gateway Detection (HTTP)");

  tag_summary =
"Detection of Symantec Messaging Gateway.

The script sends a connection request to the server and attempts to
extract the version number from the reply.";

  script_tag(name : "summary" , value : tag_summary);

  script_summary("Checks for the presence of Symantec Messaging Gateway (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

sgPort = get_http_port(default:80);

url = '/brightmail/viewLogin.do';
req = http_get(item:url, port:sgPort);
buf = http_keepalive_send_recv(port:sgPort, data:req, bodyonly:FALSE);
if( buf == NULL )continue;

if( egrep( pattern:"<title>Symantec Messaging Gateway -&nbsp;Login", string:buf, icase:TRUE ) ||
  ( "Symantec Messaging Gateway -&nbsp;" >< buf && "Symantec Corporation" >< buf && "images/Symantec_Logo.png" >< buf ) ||
  "<title>Symantec Messaging Gateway -&nbsp;Error 403</title>" >< buf )
{
  version = eregmatch( string: buf, pattern: "Version ([0-9.]+)",icase:TRUE );

  if( ! isnull( version[1] ) )
    set_kb_item( name:"symantec_messaging_gateway/version/http", value:version[1] );

  replace_kb_item( name:"smg/installed", value:TRUE );
}

exit(0);
