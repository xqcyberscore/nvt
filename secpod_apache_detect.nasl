###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apache_detect.nasl 4249 2016-10-12 06:05:18Z cfi $
#
# Apache Web Server Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900498");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 4249 $");
  script_tag(name:"last_modification", value:"$Date: 2016-10-12 08:05:18 +0200 (Wed, 12 Oct 2016) $");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Apache Web Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl", "apache_server_info.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of installed version of Apache Web Server

  The script detects the version of Apache HTTP Server on remote host and sets the KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");
include("global_settings.inc");

port = get_http_port( default:80 );

server_info_banner = get_kb_item( 'www/server-info/banner/' + port );
banner = get_http_banner( port:port );

sndReq = http_get( item: "/non-existent", port:port );
rcvRes = http_keepalive_send_recv( port:port, data:sndReq, bodyonly:FALSE );

# If banner is changed by e.g. mod_security but default error page still exists
errorPage = eregmatch( pattern:"<address>.* Server at .* Port ([0-9.]+)</address>", string:rcvRes );

if( ( "Apache" >!< banner || "Apache-" >< banner ) && "Apache" >!< server_info_banner && isnull( errorPage ) ) {
  exit( 0 );
}

tmpVer = eregmatch( pattern:"Server: Apache/([0-9]\.[0-9]+\.[0-9][0-9]?)",
                    string:banner );

if( isnull ( tmpVer[1] ) ) {
  tmpVer = eregmatch( pattern:"Server: Apache/([0-9]\.[0-9]+\.[0-9][0-9]?)",
                      string:server_info_banner );
}  

if( tmpVer[1] ) {
  apacheVer = tmpVer[1];
} else {

  ## Send and Receive the response
  req = http_get( item:"/manual/en/index.html",  port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  tmpVer = eregmatch( pattern:"<title>Apache HTTP Server Version ([0-9]\.[0-9]+).*Documentation - Apache HTTP Server.*</title>",
                      string:res );

  if( tmpVer[1] ) {
    apacheVer = tmpVer[1];
  } else {
    apacheVer = 'unknown';
  }
}

set_kb_item( name:"www/" + port + "/Apache", value:apacheVer );

set_kb_item( name:'apache/installed', value:TRUE );
   
## build cpe and store it as host_detail
cpe = build_cpe( value:apacheVer, exp:"^([0-9.]+)", base:"cpe:/a:apache:http_server:" );
if( isnull( cpe ) )
   cpe = "cpe:/a:apache:http_server";

register_product( cpe:cpe, location:port + '/tcp', port:port );
log_message( data:build_detection_report( app:"Apache",
                                          version:apacheVer,
                                          install:port + '/tcp',
                                          cpe:cpe,
                                          concluded: tmpVer[0] ),
                                          port:port );

exit( 0 );
