###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_octoprint_detect_http.nasl 11880 2018-10-12 12:56:52Z mmartin $
#
# OctoPrint Version Detection (HTTP)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.107342");
  script_version("$Revision: 11880 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 14:56:52 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-10-11 16:21:34 +0200 (Thu, 11 Oct 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("OctoPrint Version Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of OctoPrint Web UI for 3D printers using HTTP.");

  script_xref(name:"URL", value:"https://octoprint.org/download/");

  exit(0);
}

include( "cpe.inc" );
include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

port = get_http_port( default: 80 );
banner = get_http_banner( port: port, file: "/", ignore_broken: FALSE );

buf = http_get_cache(item:"/", port:port);

install = "/";

conclUrl = report_vuln_url(port: port, url: "/", url_only: TRUE);

if( banner =~ 'OctoPrint' ) {
  set_kb_item( name: "octoprint/detected", value: TRUE );
  set_kb_item( name: "octoprint/detected/auth", value:TRUE);
  set_kb_item( name: "octoprint/http/port", value: port );

  vers = 'unknown';

  register_and_report_cpe(app: "OctoPrint Web UI", ver: vers, base: "cpe:/a:octoprint:octoprint:", expr: "^([0-9.]+)", insloc: install, regPort: port, conclUrl:conclUrl);
  exit ( 0 );
}

if('OctoPrint</title>' >< buf && ('octoprint.org' >< buf)) {
  set_kb_item( name: "octoprint/detected", value:TRUE);
  set_kb_item( name: "octoprint/detected/noauth", value:TRUE);
  set_kb_item( name: "octoprint/http/port", value:port);
    }
  vers = eregmatch( pattern:'var DISPLAY_VERSION = "([0-9.]+)"',
  string:buf, icase:TRUE );
    if( ! isnull( vers[1] ) ) {
    set_kb_item( name: "octoprint/http/version", value: vers[1] );
    set_kb_item( name: "octoprint/http/concluded", value: vers[0] );
    register_and_report_cpe(app: "OctoPrint Web UI", ver: vers[1], base: "cpe:/a:octoprint:octoprint:", expr: "^([0-9.]+)", insloc: install, regPort: port, conclUrl:conclUrl);

}

exit(0);
