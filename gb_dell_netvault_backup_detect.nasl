###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_netvault_backup_detect.nasl 7000 2017-08-24 11:51:46Z teissa $
#
# Dell Netvault Backup Version Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805652");
  script_version("$Revision: 7000 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-08-24 13:51:46 +0200 (Thu, 24 Aug 2017) $");
  script_tag(name:"creation_date", value:"2015-06-17 14:03:59 +0530 (Wed, 17 Jun 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Dell Netvault Backup Version Detection");

  script_tag(name: "summary" , value: "Detection of installed version of
  Dell Netvault Backup.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variables Initialization
dir  = "";
Ver = "";
cpe = "";
sndReq = "";
rcvRes = "";
netVer = "";
netPort  = "";

## Get Dell Netvault Backup Port
if(!netPort = get_http_port(default:80)){
  exit(0);
}

## Server Listening on root directory
## Send Request and Receive Response
rcvRes = http_get_cache(item:"/", port:netPort);

## Confirm application
if(rcvRes && "NetVault Backup" >< rcvRes)
{
  Ver = eregmatch(pattern:"Server:([0-9.]+)", string:rcvRes);
  if(!Ver){
    netVer = "Unknown";
  } else {
    netVer = Ver[1];
  }

  ## Set the KB
  set_kb_item(name:"www/" + netPort + "/", value:netVer);
  set_kb_item(name:"dell/netvaultbackup/installed", value:TRUE);

  ## build cpe and store it as host_detail
  cpe = build_cpe(value: netVer, exp:"([0-9.]+)", base:"cpe:/a:dell:netvault_backup:");
  if(isnull(cpe))
    cpe = "cpe:/a:dell:netvault_backup";

  ## Register Product and Build Report
  register_product(cpe:cpe, location:"/", port:netPort);
  log_message(data: build_detection_report(app: "Dell Netvault Backup",
                                           version:netVer,
                                           install:"/",
                                           cpe:cpe,
                                           concluded:Ver[0]),
                                           port:netPort);
}

exit(0);