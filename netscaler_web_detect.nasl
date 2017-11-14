###############################################################################
# OpenVAS Vulnerability Test
# $Id: netscaler_web_detect.nasl 7723 2017-11-10 06:41:18Z asteins $
#
# Citrix NetScaler Web Detection
#
# Authors:
# nnposter
#
# Copyright:
# Copyright (C) 2007 nnposter
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.80024");
  script_version("$Revision: 7723 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-10 07:41:18 +0100 (Fri, 10 Nov 2017) $");
  script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("Citrix NetScaler Web Detection");

  script_family("Product detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (c) 2007 nnposter");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www",80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.citrix.com/networking/");

  script_tag(name:"summary", value: "Detection of Citrix Netscaler Web UI.

The script sends a connection request to the server and attempts to detect Citrix Netscaler and to extract its
version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );

foreach url( make_list("/vpn/tmindex.html", "/vpn/index.html", "/", "/index.html") ) {

  res = http_get_cache( item:url, port:port );
  if( ! res ) continue;

  if (("<title>Citrix Login</title>" >!< res || res !~ 'action="(/login/do_login|/ws/login\\.pl)"') &&
      "<title>netscaler gateway</title>" >!< tolower( res ) && "<title>citrix access gateway</title>" >!< tolower( res ) )
    continue;

  replace_kb_item( name:"www/netscaler", value:TRUE );
  replace_kb_item( name:"www/netscaler/"+ port, value:TRUE );
  replace_kb_item( name:"Services/www/" + port + " /embedded", value:TRUE );
  set_kb_item( name:"citrix_netscaler/webinterface/port", value:port );

  url2 = '/epa/epa.html';
  req = http_get( item:url2, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  version = eregmatch( pattern:'var nsversion="([^;]+)";', string:buf );
  vers = 'unknown';
  cpe = 'cpe:/a:citrix:netscaler';

  if( ! isnull( version[1] ) ) {
    vers = str_replace( string:version[1], find:",", replace:"." );
    replace_kb_item( name:"citrix_netscaler/web/version", value:vers );
    replace_kb_item( name:"citrix_netscaler/found", value:TRUE );
    cpe += ':' + vers;
    concUrl = url2;
  }

  register_product( cpe:cpe, location:"/", port:port );

  log_message( data:build_detection_report( app:"Citrix NetScaler",
                                            version:vers,
                                            install:"/",
                                            cpe:cpe,
                                            concluded:version[0],
                                            concludedUrl: concUrl,
                                            extra: "Detected URL: " + url),
               port:port );
  exit( 0 );
}

exit( 0 );
