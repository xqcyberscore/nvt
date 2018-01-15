###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_matomo_detect.nasl 8412 2018-01-13 10:35:50Z cfischer $
#
# Matomo Analytics Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108317");
  script_version("$Revision: 8412 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-13 11:35:50 +0100 (Sat, 13 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-13 07:00:00 +0100 (Sat, 13 Jan 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Matomo Analytics Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://matomo.org/");

  script_tag(name:"summary", value:"The script sends a HTTP request to the server
  and attempts to identify Matomo (formerly Piwik) and its version from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/piwik", "/matomo", "/analytics", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  buf = http_get_cache( item:dir + "/index.php", port:port );

  if( buf =~ "^HTTP/1\.[01] 200" && ( eregmatch( pattern:'<title>.*Matomo.*</title>', string:buf, icase:TRUE ) ||
      ( "https://matomo.org" >< buf && "piwik.piwik_url" >< buf ) ) ) { # nb: 3.3.0 still has the piwik.pwik_url in the response

    version = "unknown";

    url = dir + "/CHANGELOG.md";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    ver = eregmatch( pattern:'## Matomo ([0-9.]+)', string:buf );

    if( ! isnull( ver[1] ) ) {
      version  = ver[1];
      conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:matomo:matomo:");
    if( isnull( cpe ) )
      cpe = "cpe:/a:matomo:matomo";

    set_kb_item( name:"www/" + port + "/matomo", value:version );
    set_kb_item( name:"matomo/installed", value:TRUE );

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Matomo",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );
