###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_zendserver_detect.nasl 10711 2018-08-01 13:58:38Z cfischer $
#
# ZendServer Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.111028");
  script_version("$Revision: 10711 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-01 15:58:38 +0200 (Wed, 01 Aug 2018) $");
  script_tag(name:"creation_date", value:"2015-08-21 18:00:00 +0200 (Fri, 21 Aug 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("ZendServer Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ZendServer/banner");

  script_tag(name:"summary", value:"The script sends a HTTP request to the server
  and attempts to extract the version from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

port = get_http_port( default:80 );
host = http_host_name( dont_add_port:TRUE );
if( !can_host_php( port:port ) ) exit( 0 );

phpList = get_http_kb_file_extensions( port:port, host:host, ext:"php" );
if(phpList) phpFiles = make_list(phpList);

if(phpFiles[0]) {
  banner = get_http_banner(port:port, file:phpFiles[0]);
} else {
  banner = get_http_banner(port:port, file:"/index.php");
}

if( "ZendServer" >!< banner ) exit( 0 );

version = 'unknown';

ver = eregmatch( pattern:'(ZendServer|-ZS)(/| |)([0-9.]+)', string:banner );

if( ! isnull( ver[3] ) ) version = ver[3];

cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:zend:zend_server:");
if( isnull( cpe ) )
  cpe = 'cpe:/a:zend:zend_server';

set_kb_item( name:"www/" + port + "/zendserver", value:version );
set_kb_item( name:"zendserver/installed", value:TRUE );

register_product( cpe:cpe, location:port + '/tcp', port:port );

log_message( data: build_detection_report( app:"ZendServer",
                                               version:version,
                                               install:port + '/tcp',
                                               cpe:cpe,
                                               concluded: ver[0]),
                                               port:port);

exit(0);
