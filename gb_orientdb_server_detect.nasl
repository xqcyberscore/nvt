###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_orientdb_server_detect.nasl 55846 2016-08-08 15:37:50 +0530 Aug$
#
# OrientDB Server Version Detection
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.808753");
  script_version("$Revision: 6701 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 15:04:06 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2016-08-08 15:37:50 +0530 (Mon, 08 Aug 2016)");
  script_name("OrientDB Server Version Detection");
  script_tag(name : "summary" , value : "Detection of installed version
  of OrientDB Server.

  This script sends HTTP GET request and try to ensure the presence of
  OrientDB Server from the response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_summary("Check for the presence of OrientDB Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 2480);
  script_mandatory_keys("OrientDB/banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

## Variable initialisation
orientdbPort = 0;
vers = "";
version = "";
banner = "";

##Get HTTP Port
orientdbPort = get_http_port(default:2480);

## Confirm the application from banner
banner = get_http_banner(port:orientdbPort);
if("OrientDB Server" >!< banner) {
  exit(0);
}

## Grep the version from banner
vers = eregmatch(pattern:"OrientDB Server v.([0-9.]+)", string:banner);
if(vers[1]){
  version = vers[1];
}
else{
  version ="Unknown";
}

## Set the KB
set_kb_item(name:"www/" + orientdbPort + "/OrientDB/Server", value:version);
set_kb_item(name:"OrientDB/Server/Installed", value:TRUE);

## build cpe and store it as host_detail
cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:orientdb:orientdb:");
if(!cpe)
  cpe= "cpe:/a:orientdb:orientdb";

register_product(cpe:cpe, location:'/', port:orientdbPort);

log_message(data: build_detection_report(app: "OrientDB Server",
                                         version: version,
                                         install:'/',
                                         cpe: cpe,
                                         concluded: version),
                                         port: orientdbPort);
exit(0);
