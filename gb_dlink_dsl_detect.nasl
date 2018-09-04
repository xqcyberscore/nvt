###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dsl_detect.nasl 11208 2018-09-04 08:04:34Z cfischer $
#
# D-Link DSL Devices Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812377");
  script_version("$Revision: 11208 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-04 10:04:34 +0200 (Tue, 04 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-01-03 16:00:40 +0530 (Wed, 03 Jan 2018)");
  script_name("D-Link DSL Devices Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Boa_or_micro_httpd/banner");

  script_tag(name:"summary", value:"Detection of D-Link DSL Devices.

  The script sends a connection request to the server and attempts to
  determine if the remote host is a D-Link DSL device from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("cpe.inc");

port = get_http_port( default:80 );

foreach url( make_list( "/", "/cgi-bin/webproc" ) ) {

  res = http_get_cache( port:port, item:url );

  if( ( ( "Server: micro_httpd" >< res || "Server: Boa" >< res ) && ( 'WWW-Authenticate: Basic realm="DSL-' >< res || "<title>D-Link DSL-" >< res ) ) ||
        ( "DSL Router" >< res && res =~ "Copyright.*D-Link Systems" ) ) {

    conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
    install  = port + "/tcp";
    version  = "unknown";
    model    = "unknown";
    base_cpe = "cpe:/h:dlink:dsl";
    app      = "D-Link DSL";
    set_kb_item( name:"host_is_dlink_dsl", value:TRUE );

    mo = eregmatch( pattern:"DSL-([0-9A-Z]+)", string:res );
    if( mo[1] ) {
      set_kb_item(name:"D-Link/DSL/model", value:mo[1]);
      model = mo[1];
      base_cpe += "-" + tolower( model );
      app += "-" + model;
      concluded = mo[1];
    }

    # nb: Not available on all DLS- devices
    url2 = "/ayefeaturesconvert.js";
    req = http_get( port:port, item:url2 );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
    vers = eregmatch( string:res, pattern:'var AYECOM_FWVER="([0-9]\\.[0-9]+)";' );
    if( vers[1] ) {
      version = vers[1];
      if( conclUrl ) conclUrl += '\n';
      conclUrl += report_vuln_url( port:port, url:url2, url_only:TRUE );
      if( concluded ) concluded += '\n';
      concluded += vers[0];
    }

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:base_cpe + ":" );
    if( isnull( cpe ) )
      cpe = base_cpe;

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:app,
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:concluded,
                                              concludedUrl:conclUrl ),
                                              port:port );
    exit( 0 );
  }
}

exit( 0 );