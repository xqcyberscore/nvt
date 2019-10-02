###############################################################################
# OpenVAS Vulnerability Test
#
# elFinder Detection
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, https://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.113323");
  script_version("2019-10-01T08:41:24+0000");
  script_tag(name:"last_modification", value:"2019-10-01 08:41:24 +0000 (Tue, 01 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-01-11 11:46:47 +0100 (Fri, 11 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("elFinder Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Checks whether elFinder is installed on the target system
  and if so, tries to figure out the version.");

  script_xref(name:"URL", value:"https://studio-42.github.io/elFinder/");

  exit(0);
}

CPE = "cpe:/a:studio42:elfinder:";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "cpe.inc" );

port = get_http_port( default: 80 );

foreach location( make_list_unique ( "/", cgi_dirs( port: port ) ) ) {
  url = location;
  if( url == "/" )
    url = "";

  buf = http_get_cache( port: port, item: location );
  if( buf !~ "^HTTP/1\.[01] 200" || buf !~ 'elfinder' )
    continue;

  link = eregmatch( string: buf, pattern: '(src|href)="/?([^"]*elfinder\\.(min|full|version)\\.?(css|js))"', icase: TRUE );
  if( isnull( link[2] ) )
    continue;

  set_kb_item( name: "studio42/elfinder/detected", value: TRUE );

  conclUrl = url + "/" + link[2];

  version = "unknown";

  buf = http_get_cache( port: port, item: conclUrl );
  if( buf =~ "^HTTP/1\.[01] 200" ) {
    buf = ereg_replace( pattern: '[\r\n]+', string: buf, replace: '' );
    ver = eregmatch( string: buf, pattern: 'elFinder - file manager for web[ ]*\\*[ ]*Version ([0-9.]+)', icase: TRUE );
    if( isnull( ver[1] ) ) {
      ver = eregmatch( string: buf, pattern: 'elFinder[.][^.]*[.]?version[ ]*=[ ]*.([0-9.]+).', icase: TRUE );
    }
    if( ! isnull( ver[1] ) ) {
      version = ver[1];
    }
  }

  register_and_report_cpe( app: "elFinder",
                           ver: version,
                           concluded: ver[0],
                           base: CPE,
                           expr: '([0-9.]+)',
                           insloc: location,
                           regPort: port,
                           regService: "www",
                           conclUrl: conclUrl );

  exit( 0 );
}

exit( 0 );
