# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113391");
  script_version("2019-08-05T11:12:31+0000");
  script_tag(name:"last_modification", value:"2019-08-05 11:12:31 +0000 (Mon, 05 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-05-16 10:16:17 +0200 (Thu, 16 May 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Crestron AirMedia Presentation Gateway Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Crestron AirMedia Presentation
  Gateway devices.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:443 );

url = "/cgi-bin/login.cgi?lang=en&src=AwLoginDownload.html";

buf = http_get_cache( item:url, port:port );

if( buf =~ '^HTTP/[0-9]([.][0-9]+)? 200' && '<title>Crestron AirMedia</title>' >< buf ) {
  detected = TRUE;
} else {
  url = "/index_airmedia.html";
  buf = http_get_cache( item:url, port:port );

  if( buf =~ '^HTTP/[0-9]([.][0-9]+)? 200' &&
      ( "<title>Crestron AirMedia</title>" >< buf && "Crestron Webserver" >< buf ) ) {
    detected = TRUE;
  }
}

if( detected ) {
  set_kb_item( name:"crestron_airmedia/detected", value:TRUE );
  set_kb_item( name:"crestron_airmedia/http/detected", value:TRUE );
  set_kb_item( name:"crestron_airmedia/http/port", value:port );
  set_kb_item( name:"crestron_airmedia/http/" + port + "/concludedUrl", value:url);
}

exit( 0 );
