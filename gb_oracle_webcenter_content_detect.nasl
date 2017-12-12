###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_webcenter_content_detect.nasl 8078 2017-12-11 14:28:55Z cfischer $
#
# Oracle WebCenter Content Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811709");
  script_version("$Revision: 8078 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-11 15:28:55 +0100 (Mon, 11 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-08-18 12:44:35 +0530 (Fri, 18 Aug 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Oracle WebCenter Content Detection");

  script_tag(name: "summary" , value: "Detection of installed version of
  Oracle WebCenter Content.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

##
### Code Starts Here
##

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variables Initialization
cpe = "";
sndReq = "";
rcvRes = "";
owPort  = "";
owVer = "";
owVer = "";
version = "";

##Get Port
owPort = get_http_port(default:80);
if(!owPort){
  exit(0);
}

## Send request and receive response
sndReq = http_get(item:"/cs/login/login.htm", port:owPort);
rcvRes = http_keepalive_send_recv(port:owPort, data:sndReq);

## Confirm the application from response
if(rcvRes && "<title>Oracle WebCenter Content Sign In<" >< rcvRes &&
   rcvRes =~ "Copyright.*Oracle")
{
  owVer = "unknown";
  set_kb_item(name:"Oracle/WebCenter/Content/Installed", value:TRUE);

  ## build cpe and store it as host_detail
  ## Created new cpe
  cpe = "cpe:/a:oracle:webcenter_content";

  ##Register Product and Build Report
  register_product(cpe:cpe, location:"/", port:owPort);
  log_message(data: build_detection_report(app: "Oracle WebCenter Content",
                                           version:owVer,
                                           install:"/",
                                           cpe:cpe,
                                           concluded:owVer),
                                           port:owPort);
  exit(0);
}
exit(0);
