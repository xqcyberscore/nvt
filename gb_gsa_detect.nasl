###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gsa_detect.nasl 9128 2018-03-19 07:45:38Z cfischer $
#
# Greenbone Security Assistant Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.103841");
  script_version("$Revision: 9128 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-03-19 08:45:38 +0100 (Mon, 19 Mar 2018) $");
  script_tag(name:"creation_date", value:"2013-11-29 14:30:41 +0100 (Fri, 29 Nov 2013)");
  script_name("Greenbone Security Assistant Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443, 9392);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to
  determine if it is a GSA from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

port = get_http_port( default:9392 );

url = "/login/login.html";
buf = http_get_cache( item:url, port:port );

if( buf =~ "^HTTP/1\.[01] 200" && "Greenbone Security Assistant" >< buf ) {

  install = "/";
  vers    = "unknown";
  version = eregmatch( string:buf, pattern:'<span class="version">Version ([^<]+)</span>', icase:FALSE );
  if( ! isnull( version[1] ) ) vers = version[1];

  set_kb_item( name:"gsa/installed", value:TRUE );
  set_kb_item( name:"gsa/" + port + "/version", value:vers );
  set_kb_item( name:"gsa_or_gsa_ng/" + port + "/detected", value:TRUE );
  set_kb_item( name:"openvas_framework_component/installed", value:TRUE );

  cpe = build_cpe( value:vers, exp:"^([0-9.-]+)", base:"cpe:/a:greenbone:greenbone_security_assistant:" );
  if( isnull( cpe ) )
    cpe = "cpe:/a:greenbone:greenbone_security_assistant";

  register_product( cpe:cpe, location:install, port:port );
  log_message( data:build_detection_report( app:"Greenbone Security Assistant",
                                            version:vers,
                                            concluded:version[0],
                                            install:install,
                                            cpe:cpe ),
                                            port:port );
  exit( 0 );
}

url = "/login";
buf = http_get_cache( item:url, port:port );

if( buf =~ "^HTTP/1\.[01] 200" && "<title>Greenbone Security Assistant NG</title>" >< buf ) {

  install = "/";
  vers    = "unknown";

  set_kb_item( name:"gsa_ng/installed", value:TRUE );
  set_kb_item( name:"gsa_ng/" + port + "/version", value:vers );
  set_kb_item( name:"gsa_or_gsa_ng/" + port + "/detected", value:TRUE );
  set_kb_item( name:"openvas_components/installed", value:TRUE );

  cpe = build_cpe( value:vers, exp:"^([0-9.-]+)", base:"cpe:/a:greenbone:greenbone_security_assistant_ng:" );
  if( isnull( cpe ) )
    cpe = "cpe:/a:greenbone:greenbone_security_assistant_ng";

  register_product( cpe:cpe, location:install, port:port );
  log_message( data:build_detection_report( app:"Greenbone Security Assistant NG",
                                            version:vers,
                                            install:install,
                                            cpe:cpe ),
                                            port:port );
}

exit( 0 );
