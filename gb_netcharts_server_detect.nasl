###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netcharts_server_detect.nasl 6063 2017-05-03 09:03:05Z teissa $
#
# NetCharts Server Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.805642");
  script_version("$Revision: 6063 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-05-03 11:03:05 +0200 (Wed, 03 May 2017) $");
  script_tag(name:"creation_date", value:"2015-06-03 12:12:21 +0530 (Wed, 03 Jun 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("NetCharts Server Version Detection");

  script_tag(name: "summary" , value: "Detection of installed version of
  Visual Mining NetCharts Server.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 8001);
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
ncPort  = "";
dir  = "";
sndReq = "";
rcvRes = "";
ncVer = "";
cpe = "";
url = "";

##Get NetCharts Server Port
ncPort = get_http_port(default:8001);
if(!ncPort){
  exit(0);
}

##Server Listening on root directory
##Send Request and Receive Response
sndReq = http_get(item:string("/Documentation/misc/about.jsp"), port:ncPort);
rcvRes = http_keepalive_send_recv(port:ncPort, data:sndReq);

#Confirm application
if(rcvRes && "NetCharts Server" >< rcvRes && "Visual Mining" >< rcvRes)
{
  Ver = eregmatch(pattern:"Version.*[0-9.]+.*&copy", string:rcvRes);
  ncVer = eregmatch(pattern:"([0-9.]+)", string:Ver[0]);
  if(!ncVer){
    ncVer = "Unknown";
  } else{
    ncVer = ncVer[0];
  }

  ## Set the KB
  set_kb_item(name:"www/" + ncPort + "/", value:ncVer);
  set_kb_item(name:"netchart/installed",value:TRUE);

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:ncVer, exp:"^([0-9.]+)", base:"cpe:/a:visual_mining:netcharts_server:");
  if(isnull(cpe))
    cpe = "cpe:/a:visual_mining:netcharts_server";

  register_product(cpe:cpe, location:dir, port:ncPort);
  log_message(data: build_detection_report(app:"Visual Mining/NetChart",
                                           version:ncVer,
                                           install:"/",
                                           cpe:cpe,
                                           concluded:ncVer),
                                           port:ncPort);
}
