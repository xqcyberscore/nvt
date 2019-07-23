###############################################################################
# OpenVAS Vulnerability Test
#
# Hudson CI Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.111000");
  script_version("2019-07-22T13:29:20+0000");
  script_tag(name:"last_modification", value:"2019-07-22 13:29:20 +0000 (Mon, 22 Jul 2019)");
  script_tag(name:"creation_date", value:"2015-03-02 12:00:00 +0100 (Mon, 02 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Hudson CI Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a HTTP
  request to the server and attempts to extract the version from
  the reply.");

  script_tag(name:"qod_type", value:"remote_banner");


  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:8080 );

foreach dir( make_list_unique( cgi_dirs( port:port ), "/hudson" ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  buf = http_get_cache( item:dir + "/", port:port );

  if( ( "Welcome to Hudson!" >< buf || "X-Hudson:" >< buf || "<title>Dashboard [Hudson]</title>" >< buf ) && "X-Jenkins:" >!< buf ) {

    version = 'unknown';
    ver = eregmatch( pattern:'Hudson ver. ([0-9.]+[0-9.]+[0-9.])', string:buf );

    if( ! isnull( ver[1] ) ) {
      version = ver[1];
    } else {
      ver = eregmatch( pattern:'Hudson: ([0-9.]+[0-9.]+[0-9.])', string:buf );
      if( ! isnull( ver[1] ) )
        version = ver[1];
    }

    set_kb_item( name:"hudson/detected", value:TRUE );
    set_kb_item( name:"hudson/http/port", value:port );
    set_kb_item( name:"hudson/http/" + port + "/location", value:install );

    if( version != "unknown" ) {
      set_kb_item( name:"hudson/http/" + port + "/version", value:version );
      set_kb_item( name:"hudson/http/" + port + "/concluded", value:ver[0] );
    }

    exit( 0 ); # nb: Avoid multiple detections on the "X-Hudson:" pattern
  }
}

exit( 0 );
