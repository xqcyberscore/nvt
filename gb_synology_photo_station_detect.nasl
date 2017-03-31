###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_synology_photo_station_detect.nasl 2664 2016-02-16 07:43:49Z antu123 $
#
# Synology Photo Station Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105279");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version ("$Revision: 2664 $");
 script_tag(name:"last_modification", value:"$Date: 2016-02-16 08:43:49 +0100 (Tue, 16 Feb 2016) $");
 script_tag(name:"creation_date", value:"2015-05-26 13:47:01 +0200 (Tue, 26 May 2015)");
 script_name("Synology Photo Station Detection");

 script_tag(name: "summary" , value: "The script sends a connection
request to the server and attempts to extract the version number
from the reply.");

 script_tag(name:"qod_type", value:"remote_active");

 script_summary("Checks for the presence of Synology Photo Station");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );

url = '/photo/';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf !~ "<title>Photo Station [0-9]{1}</title>" || "webapi/auth.php" >!< buf ) exit( 0 );

cpe = "cpe:/a:synology:synology_photo_station";
set_kb_item( name:"synology_photo_station/installed", value:TRUE );

psv = 'unknown';
ps_version = eregmatch( pattern:'<title>Photo Station ([0-9]{1})</title>', string:buf );
if( ! isnull( ps_version[1] ) )
{
  psv = ps_version[1];
  set_kb_item( name:"synology_photo_station/psv", value:psv );
}

vers = 'unknown';
lines = split( buf, keep:FALSE );
foreach line ( lines )
{
  if( version = eregmatch( pattern:"(.php|.js)\?v=([0-9.-]+)", string:line ) )
  {
    if( ! isnull( version[2] ) )
    {
      vers = version[2];
      cpe += ':' + vers;
      set_kb_item( name:"synology_photo_station/version", value: vers );
      break;
    }
  }
}


register_product( cpe:cpe, location:url, port:port );

log_message( data: build_detection_report( app:"Synology Photo Station " + psv,
                                           version:vers,
                                           install:url,
                                           cpe:cpe,
                                           concluded: version[0] ),
             port:port );

exit(0);

