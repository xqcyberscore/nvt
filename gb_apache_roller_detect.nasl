##############################################################################
# OpenVAS Vulnerability Test
#
# Apache Roller Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800677");
  script_version("2019-07-23T10:31:33+0000");
  script_tag(name:"last_modification", value:"2019-07-23 10:31:33 +0000 (Tue, 23 Jul 2019)");
  script_tag(name:"creation_date", value:"2009-08-12 19:54:51 +0200 (Wed, 12 Aug 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Apache Roller Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of Apache Roller.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:8080 );

files = make_list( "/login.rol", "/index.jsp" );

foreach dir( make_list_unique( "/roller", "/roller-ui", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  foreach file( files ) {

    url = dir + file;

    res = http_get_cache( item:url, port:port );

    if( res =~ "^HTTP/1\.[01] 200" && ( "Welcome to Roller" >< res || res =~ "Platform based on <[^>]+Roller" ) ) {

      version = "unknown";

      ver = eregmatch( pattern:'</a> Version ([0-9.]+)', string:res );
      if( ver[1] )
        version = ver[1];

      set_kb_item( name:"ApacheRoller/detected", value:TRUE );

      cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apache:roller:" );
      if( ! cpe  )
        cpe = 'cpe:/a:apache:roller';

      register_product( cpe:cpe, location:install, port:port, service:"www" );

      log_message( data:build_detection_report( app:"Apache Roller",
                                                version:version,
                                                install:install,
                                                cpe:cpe,
                                                concluded:ver[0],
                                                concludedUrl:report_vuln_url( port:port, url:url, url_only:TRUE ) ),
                   port:port );
    }
  }
}

exit( 0 );
