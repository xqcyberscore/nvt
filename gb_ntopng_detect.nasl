###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ntopng_detect.nasl 4854 2016-12-26 17:10:14Z cfi $
#
# ntopng Version Detection
#
# Authors:
# Tameem Eissa <tameem.eissa..at..greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107109");
  script_version("$Revision: 4854 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-26 18:10:14 +0100 (Mon, 26 Dec 2016) $");
  script_tag(name:"creation_date", value:"2016-12-20 06:40:16 +0200 (Tue, 20 Dec 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("ntopng Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 3000);
  script_exclude_keys("Settings/disable_cgi_scanning"); 

  script_tag(name:"summary", value:"Detection of installed version of ntopng

  The script detects the version of ntopng on remote host and sets the KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

appPort = get_http_port( default:3000 );

foreach dir( make_list_unique( "/", cgi_dirs( port:appPort ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/lua/login.lua?referer=/";

  sndReq = http_get( item:url, port:appPort );
  rcvRes = http_keepalive_send_recv( port:appPort, data:sndReq );

  if ( "erver: ntopng" >!< rcvRes && "<title>Welcome to ntopng</title>" >!< rcvRes && "ntop.org<br> ntopng is released under" >!< rcvRes ) continue;

  tmpVer = eregmatch( string:rcvRes, pattern:"Server: ntopng ([0-9.]+)", icase:TRUE );
  if( tmpVer[1] ) {
    ntopngVer = tmpVer[1];
    set_kb_item( name:"www/" + appPort + "/ntopng", value:ntopngVer );
  }

  replace_kb_item( name:"ntopng/installed", value:TRUE );

  cpe = build_cpe( value:ntopngVer, exp:"^([0-9.]+)", base:"cpe:/a:ntop:ntopng:" );
  if( ! cpe )
    cpe = 'cpe:/a:ntop:ntopng';

  register_product( cpe:cpe, location:install, port:appPort );
  log_message( data:build_detection_report( app:"ntopng",
                                            version:ntopngVer,
                                            install:install,
                                            cpe:cpe,
                                            concluded:tmpVer[0] ),
                                            port:appPort );
}

exit( 0 );
