###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_greenbone_os_detect_http.nasl 8610 2018-01-31 15:08:13Z cfischer $
#
# Greenbone Security Manager (GSM) / Greenbone OS (GOS) Detection (HTTP)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112137");
  script_version("$Revision: 8610 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-31 16:08:13 +0100 (Wed, 31 Jan 2018) $");
  script_tag(name:"creation_date", value:"2017-11-23 10:50:05 +0100 (Thu, 23 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Greenbone Security Manager (GSM) / Greenbone OS (GOS) Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Greenbone Security Manager (GSM)
  and Greenbone OS (GOS).

  The script sends a connection request via HTTP to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:443 );

url = "/login/login.html";
buf = http_get_cache( item:url, port:port );

if( buf =~ "HTTP/1\.. 200" && ( ( "<title>Greenbone Security Assistant" >< buf && "Greenbone OS" >< buf ) ||
    '"title">Greenbone Security Manager</span>' >< buf ) ) {

  set_kb_item( name:"greenbone/gos/detected", value:TRUE );
  set_kb_item( name:"greenbone/gos/http/detected", value:TRUE );
  set_kb_item( name:"greenbone/gos/http/port", value:port );
  set_kb_item( name:"greenbone/gos/http/" + port + "/detected", value:TRUE );

  vers = "unknown";
  version = eregmatch( string:buf, pattern:'<div class="gos_version">Greenbone OS ([^<]+)</div>', icase:FALSE );

  if( ! isnull( version[1] ) ) {
    vers = version[1];
    concluded = version[0];
  } else {
    version = eregmatch( string:buf, pattern:'<span class="version">Greenbone OS ([^<]+)</span>', icase:FALSE );
    if( ! isnull( version[1] ) ) {
      vers = version[1];
      concluded = version[0];
    } else {
      version = eregmatch( string:buf, pattern:'<span class="version">Version Greenbone OS ([^<]+)</span>', icase:FALSE );
      if( ! isnull( version[1] ) ) {
        vers = version[1];
        concluded = version[0];
      }
    }
  }

  type = "unknown";
  # e.g. <img src="/img/gsm-one_label.svg"></img>
  # or <img src="/img/GSM_DEMO_logo_95x130.png" alt=""></td>
  _type = eregmatch( string:buf, pattern:'<img src="/img/gsm-([^>]+)_label\\.svg"></img>', icase:FALSE );
  if( ! _type[1] ) {
    _type = eregmatch( string:buf, pattern:'<img src="/img/GSM_([^>]+)_logo_95x130\\.png" alt=""></td>', icase:FALSE );
  }

  if( _type[1] ) {
    # nb: Products are named uppercase
    type = toupper( _type[1] );
    concluded += _type[0];
  }

  set_kb_item( name:"greenbone/gos/http/" + port + "/version", value:vers );
  set_kb_item( name:"greenbone/gsm/http/" + port + "/type", value:type );

  if( concluded ) {
    set_kb_item( name:"greenbone/gos/http/" + port + "/concluded", value:concluded );
    set_kb_item( name:"greenbone/gos/http/" + port + "/concludedUrl", value:report_vuln_url( port:port, url:url, url_only:TRUE ) );
  }
}

exit( 0 );
