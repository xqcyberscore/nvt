###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_powerfolder_detection.nasl 6701 2017-07-12 13:04:06Z cfischer $
#
# Powerfolder Detection
#
# Authors:
# Tameem Eissa <tameem.eissa..at..greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107009");
  script_version("$Revision: 6701 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 15:04:06 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"creation_date", value:"2016-06-07 06:40:16 +0200 (Tue, 07 Jun 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("PowerFolder Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of installed version of PowerFolder

  The script detects the version of PowerFolder on remote host and sets the KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

appPort = get_http_port( default:80);
banner = get_http_banner( port:appPort );

url = '/login/index.html';
sndReq = http_get( item: url, port:appPort );
rcvRes = http_keepalive_send_recv( port: appPort, data:sndReq, bodyonly:FALSE );

if ( rcvRes !~ "HTTP/1\.. 200|302" || "powerfolder" >!< tolower( banner ) )
{
 url = '/login/extern/index.html';
 sndReq = http_get( item:url, port:appPort );
 rcvRes = http_keepalive_send_recv( port:appPort, data:sndReq, bodyonly:FALSE);
 if ( rcvRes !~ "HTTP/1\.. 200|302" || "powerfolder" >!< tolower(banner))
 {
   exit(0);
 }
}
tmpVer = eregmatch( pattern:"Program version: ([0-9]+\.[0-9]+\.+[0-9]+?)",
                    string:rcvRes );
if(tmpVer[1] ) {
  powfolVer = tmpVer[1];
  set_kb_item( name:"www/" + appPort + "/powerfolder", value:powfolVer );
} 

set_kb_item( name:"powerfolder/installed", value:TRUE );
cpe = build_cpe(value:powfolVer, exp:"^([0-9.]+)", base:"cpe:/a:power:folder:");
if(!cpe)
  cpe = 'cpe:/a:power:folder';
register_product( cpe:cpe, location:appPort + '/tcp',port: appPort );
log_message( data:build_detection_report( app:"PowerFolder",
                                          version:powfolVer,
                                          install:appPort + '/tcp',
                                          cpe:cpe, concluded: tmpVer[0] ),
                                          port:appPort);

exit( 0 );
		 


