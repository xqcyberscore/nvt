###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jetty_detect.nasl 7531 2017-10-20 14:07:54Z cfischer $
#
# Jetty Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800953");
  script_version("$Revision: 7531 $");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-20 16:07:54 +0200 (Fri, 20 Oct 2017) $");
  script_tag(name:"creation_date", value:"2009-10-20 14:26:56 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Jetty Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Jetty Web Server.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:8080 );
banner = get_http_banner( port:port );

if( "Server: Jetty" >< banner ) {

  version = "unknown";
  installed = TRUE;

  ver = eregmatch( pattern:"Jetty.([0-9.]+)([a-zA-Z]+[0-9]+)?", string:banner );

  if( ver[1] != NULL ) {
    if( ver[2] != NULL ) {
      if(ver[2] =~ "^v") {
        ver[2] = ver[2] -"v";
      }

      if( ver[1] =~ "\.$" ) {
        version = ver[1] +  ver[2];
      } else {
        version = ver[1] + "." + ver[2];
      }
    } else {
      version = ver[1];
    }
  }
}

if( ! installed ) {

  # If banner is changed / hidden but default error page still exists.
  url = "/non-existent.html";
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE, fetch404:TRUE );

  if( res =~ "^HTTP/1\.[01] [3-5].*" && "<small>Powered by Jetty://</small>" >< res ) {
    installed = TRUE;
    conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
    # nb: Status page doesn't contain a version so just setting it as "installed"
    version = "unknown";
  }
}

if( installed ) {

  install = port + "/tcp";
  set_kb_item( name:"www/" + port + "/Jetty", value:version );
  set_kb_item( name:"Jetty/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:eclipse:jetty:" );
  if( ! cpe )
    cpe = "cpe:/a:eclipse:jetty";

   register_product( cpe:cpe, location:install, port:port );
   log_message( data:build_detection_report( app:"Jetty Web Server",
                                             version:version,
                                             install:install,
                                             cpe:cpe,
                                             concluded:ver[0],
                                             concludedUrl:conclUrl ),
                                             port:port );
}

exit( 0 );
