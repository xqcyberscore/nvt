###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dup_scount_enterprise_detect.nasl 6032 2017-04-26 09:02:50Z teissa $
#
# Dup Scout Enterprise Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.809064");
  script_version("$Revision: 6032 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-26 11:02:50 +0200 (Wed, 26 Apr 2017) $");
  script_tag(name:"creation_date", value:"2016-10-13 16:11:25 +0530 (Thu, 13 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Dup Scout Enterprise Version Detection");

  script_tag(name: "summary" , value: "Detection of installed version of
  Dup Scout Enterprise.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 8080);
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
dupPort  = "";
dupVer = "";

##Get Disk Pulse Enterprise server Port
dupPort = get_http_port(default:8080);
if(!dupPort){
  exit(0);
}

## Send request and receive response
sndReq = http_get(item:"/login", port:dupPort);
rcvRes = http_keepalive_send_recv(port:dupPort, data:sndReq);

## Confirm the server from response
if(">Dup Scout Enterprise" >< rcvRes &&
   ">User Name" >< rcvRes && ">Password" >< rcvRes)
{
  dupVer = eregmatch(pattern:">Dup Scout Enterprise v([0-9.]+)", string:rcvRes);
  if(dupVer[1]){
    dupVer = dupVer[1];
  } else {
    dupVer = "Unknown";
  }

  ##Set the KB
  set_kb_item(name:"Dup/Scout/Enterprise/installed", value:TRUE);

  ## build cpe and store it as host_detail
  ## Created new cpe
  cpe = build_cpe(value:dupVer, exp:"([0-9.]+)", base:"cpe:/a:dup:dup_scout_enterprise:");
  if(isnull(cpe))
    cpe = "cpe:/a:dup:dup_scout_enterprise";

  ##Register Product and Build Report
  register_product(cpe:cpe, location:"/", port:dupPort);
  log_message(data: build_detection_report(app: "Dup Scout Enterprise",
                                           version:dupVer,
                                           install:"/",
                                           cpe:cpe,
                                           concluded:dupVer),
                                           port:dupPort);
}
exit(0);
