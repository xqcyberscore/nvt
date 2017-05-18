###############################################################################
# OpenVAS Vulnerability Test
# $Id: nginx_detect.nasl 6032 2017-04-26 09:02:50Z teissa $
#
# nginx Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100274");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 6032 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-26 11:02:50 +0200 (Wed, 26 Apr 2017) $");
  script_tag(name:"creation_date", value:"2009-10-01 18:57:31 +0200 (Thu, 01 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("nginx Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "gb_php_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of nginx.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("global_settings.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

banner = get_http_banner( port:port );
if( ! banner ) exit( 0 );

if( egrep( pattern:"Server: nginx", string:banner, icase:TRUE ) ) {

  vers = "unknown";

  ### try to get version 
  version = eregmatch( string:banner, pattern:"Server: nginx/([0-9.]+)", icase:TRUE );

  if( ! isnull( version[1] ) ) {
    vers = chomp( version[1] );
  } else {
    # Some configs are reporting the version in the banner if a index.php is called
    phpList = get_kb_list( "www/" + port + "/content/extensions/php" );
    if( phpList ) phpFiles = make_list( phpList );

    if( phpFiles[0] ) {
      banner = get_http_banner( port:port, file:phpFiles[0] );
    } else {
      banner = get_http_banner( port:port, file:"/index.php" );
    }

    version = eregmatch( string:banner, pattern:"Server: nginx/([0-9.]+)", icase:TRUE );

    if( ! isnull( version[1] ) ) {
      vers = chomp( version[1] );
    }
  }

  set_kb_item( name:"nginx/" + port + "/version", value:vers );
  set_kb_item( name:"nginx/installed", value:TRUE );

  ## build cpe and store it as host_detail
  cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:nginx:nginx:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:nginx:nginx';

  register_product( cpe:cpe, location:port + '/tcp', port:port );

  log_message( data:build_detection_report( app:"nginx",
                                            version:vers,
                                            install:port + '/tcp',
                                            cpe:cpe,
                                            concluded:version[0] ),
                                            port:port );
}

exit( 0 );
