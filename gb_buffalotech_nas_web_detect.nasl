###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_buffalotech_nas_web_detect.nasl 10839 2018-08-08 12:35:37Z asteins $
#
# Buffalotech NAS Detection
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112353");

  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_version("$Revision: 10839 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-08 14:35:37 +0200 (Wed, 08 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-08-08 13:38:12 +0200 (Wed, 08 Aug 2018)");

  script_name("Buffalotech NAS Detection");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 9000);
  script_exclude_keys("Settings/disable_cgi_scanning");


  script_tag(name:"summary", value:"Detection of Buffalo LinkStation / TeraStation Network Attached Storage devices.

  The script sends a connection request to the server and attempts to
  determine if the remote host is a LinkStation / TeraStation device from the reply.");

  exit(0);
}

include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "cpe.inc" );
include( "host_details.inc" );

CPE = "cpe:/h:buffalotech:nas:";
fingerprint = "b810a5f2a0528eafd7d23e25380aa03d";

port = get_http_port( default:9000 );

foreach dir ( make_list_unique( "/", "/ui", cgi_dirs( port: port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  res = http_get_cache( item: dir + "/", port: port );

  logo_req = http_get( port: port, item: dir + "/images/logo.png" );
  logo_res = http_keepalive_send_recv( port: port, data: logo_req, bodyonly: TRUE );

  if( ! isnull( logo_res  ) ) {
    md5 = hexstr( MD5( logo_res ) );
  }

  if( '<title>WebAccess</title>' >< res && 'xtheme-buffalo.css">' >< res && fingerprint == md5 ) {

    set_kb_item( name: "buffalo/linkstation_or_terastation/detected", value: TRUE );
    set_kb_item( name: "buffalo/nas/detected", value: TRUE );
    set_kb_item( name: "buffalo/nas/http/port", value: port );

    version = "unknown";

    register_and_report_cpe( app: "Buffalo LinkStation / TeraStation",
                             ver: version,
                             base: CPE,
                             expr: '([0-9.]+)',
                             insloc: install,
                             regPort: port,
                             conclUrl: dir);

  }
}

exit(0);
