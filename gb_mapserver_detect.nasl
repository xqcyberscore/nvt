###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mapserver_detect.nasl 9608 2018-04-25 13:33:05Z jschulte $
#
# MapServer Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.800547");
  script_version("$Revision: 9608 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-25 15:33:05 +0200 (Wed, 25 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-04-08 08:04:29 +0200 (Wed, 08 Apr 2009)");
  script_name("MapServer Version Detection");
  script_tag(name:"summary", value:"Detection of installed version
  of MapServer.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

mapPort = "";
sndReq = "";
rcvRes = "";
mapVer = "";

if(!mapPort = get_http_port(default:80)){
  exit(0);
}

## Send and receive response and Confirm the application
sndReq = http_get(item:string("/cgi-bin/mapserv?map="), port:mapPort);
rcvRes = http_keepalive_send_recv(port:mapPort, data:sndReq, bodyonly:1);

if("MapServer" >!< rcvRes)
{
  sndReq = http_get(item: string("/cgi-bin/mapserv.exe?map="), port:mapPort);
  rcvRes = http_keepalive_send_recv(port:mapPort, data:sndReq, bodyonly:1);
  if("MapServer" >!< rcvRes){
    exit(0);
  }
}

mapVer = eregmatch(pattern:"MapServer version ([0-9]\.[0-9.]+)", string:rcvRes);
if( mapVer[1] )
{
  version = mapVer[1];
  set_kb_item(name:"MapServer/ver", value:version);
}
else{
  version = "unknown";
}

set_kb_item(name:"MapServer/Installed", value:TRUE);

cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:umn:mapserver:");
if(!cpe)
  cpe= "cpe:/a:umn:mapserver";
register_product(cpe:cpe, location:"/", port:mapPort);
log_message(data: build_detection_report(app: "MapServer",
                                         version: version,
                                         install: "/",
                                         cpe: cpe,
                                         concluded: version),
                                         port:mapPort);
exit(0);
