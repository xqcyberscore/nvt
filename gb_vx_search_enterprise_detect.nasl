###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vx_search_enterprise_detect.nasl 9633 2018-04-26 14:07:08Z jschulte $
#
# VX Search Enterprise Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.809060");
  script_version("$Revision: 9633 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-26 16:07:08 +0200 (Thu, 26 Apr 2018) $");
  script_tag(name:"creation_date", value:"2016-10-10 10:19:35 +0530 (Mon, 10 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("VX Search Enterprise Version Detection");

  script_tag(name: "summary" , value: "Detection of installed version of
  VX Search Enterprise.

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
vxPort  = "";
vxVer = "";

vxPort = get_http_port(default:80);
if(!vxPort){
  exit(0);
}

## Send request and receive response
sndReq = http_get(item:"/login", port:vxPort);
rcvRes = http_keepalive_send_recv(port:vxPort, data:sndReq);

if(">VX Search Enterprise" >< rcvRes &&
   ">User Name" >< rcvRes && ">Password" >< rcvRes)
{
  vxVer = eregmatch(pattern:">VX Search Enterprise v([0-9.]+)", string:rcvRes);
  if(vxVer[1]){
    vxVer = vxVer[1];
  } else {
    vxVer = "Unknown";
  }

  set_kb_item(name:"VX/Search/Enterprise/installed", value:TRUE);

  ## Created new cpe
  cpe = build_cpe(value:vxVer, exp:"([0-9.]+)", base:"cpe:/a:vx:search_enterprise:");
  if(isnull(cpe))
    cpe = "cpe:/a:vx:search_enterprise";

  register_product(cpe:cpe, location:"/", port:vxPort);
  log_message(data: build_detection_report(app: "VX Search Enterprise",
                                           version:vxVer,
                                           install:"/",
                                           cpe:cpe,
                                           concluded:vxVer),
                                           port:vxPort);
  exit(0);
}
exit(0);
