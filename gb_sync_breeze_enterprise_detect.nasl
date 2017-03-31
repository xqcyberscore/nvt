###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sync_breeze_enterprise_detect.nasl 5499 2017-03-06 13:06:09Z teissa $
#
# Sync Breeze Enterprise Version Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809058");
  script_version("$Revision: 5499 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-06 14:06:09 +0100 (Mon, 06 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-10-10 10:19:35 +0530 (Mon, 10 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Sync Breeze Enterprise Version Detection");

  script_tag(name: "summary" , value: "Detection of installed version of
  Sync Breeze Enterprise.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

##
### Code Starts Here
##

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variables Initialization
cpe = "";
sndReq = "";
rcvRes = "";
syncPort  = "";
syncVer = "";

##Get Disk Pulse Enterprise server Port
syncPort = get_http_port(default:80);
if(!syncPort){
  exit(0);
}

## Send request and receive response
sndReq = http_get(item:"/login", port:syncPort);
rcvRes = http_keepalive_send_recv(port:syncPort, data:sndReq);

## Confirm the server from response
if(">Sync Breeze Enterprise" >< rcvRes &&
   ">User Name" >< rcvRes && ">Password" >< rcvRes)
{
  syncVer = eregmatch(pattern:">Sync Breeze Enterprise v([0-9.]+)", string:rcvRes);
  if(syncVer[1]){
    syncVer = syncVer[1];
  } else {
    syncVer = "Unknown";
  }

  ##Set the KB
  set_kb_item(name:"Sync/Breeze/Enterprise/installed", value:TRUE);

  ## build cpe and store it as host_detail
  ## Created new cpe
  cpe = build_cpe(value:syncVer, exp:"([0-9.]+)", base:"cpe:/a:sync:sync_breeze_enterprise:");
  if(isnull(cpe))
    cpe = "cpe:/a:sync:sync_breeze_enterprise";

  ##Register Product and Build Report
  register_product(cpe:cpe, location:"/", port:syncPort);
  log_message(data: build_detection_report(app: "Sync Breeze Enterprise",
                                           version:syncVer,
                                           install:"/",
                                           cpe:cpe,
                                           concluded:syncVer),
                                           port:syncPort);
  exit(0);
}
exit(0);
