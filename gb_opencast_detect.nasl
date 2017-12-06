###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opencast_detect.nasl 7994 2017-12-05 13:47:58Z jschulte $
#
# Opencast detection
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113057");
  script_version("$Revision: 7994 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-05 14:47:58 +0100 (Tue, 05 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-11-29 13:56:41 +0100 (Wed, 29 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Opencast detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script sends an HTTP GET request to figure out whether Opencast is running on the target host, and, if so, which version is installed.");

  script_xref(name:"URL", value:"http://www.opencast.org");

  exit( 0 );
}

include( "cpe.inc" );
include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

port = get_http_port( default: 80 );
foreach dir ( make_list_unique( "/", "/admin-ng", cgi_dirs( port: port ) ) ) {

  foreach file ( make_list( "/", "/login.html" ) ) {

    if( dir == "/" ) url = file;
    else url = dir + file;
    resp = http_get_cache( item: url, port: port );

    if( resp =~ "<title>Opencast[^<]{0,}" && ( resp =~ 'version.version"> Opencast' || resp =~ 'href="http://www.opencastproject.org"' ) ) {

      version_url = "/sysinfo/bundles/version";
      resp = http_get_cache( item: version_url, port: port );
      version_match = eregmatch( pattern: '"version":"([0-9].[0-9].[0-9])', string: resp );
      version = "unknown";
      if ( version_match[1] ) version = version_match[1];

      set_kb_item( name: "opencast/detected", value: TRUE );
      cpe = build_cpe( value: version, exp: '([0-9].[0-9].[0-9])', base: "cpe:/a:opencast:opencast:");
      if( !cpe ) cpe = "cpe:/a:opencast:opencast";

      if( dir == "/" ) concluded_url = version_url;
      else conluded_url = dir + version_url;
      # Build Report and register product
      build_report( app: "Opencast", ver: version, concluded: version_match[0], conclUrl: concluded_url, cpe: cpe, insloc: dir, port: port );

      exit( 0 );

    }
  }
}
