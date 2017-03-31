###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_disk_savvy_enterprise_server_detect.nasl 4677 2016-12-05 13:46:19Z antu123 $
#
# Disk Savvy Enterprise Server Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.809485");
  script_version("$Revision: 4677 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-12-05 14:46:19 +0100 (Mon, 05 Dec 2016) $");
  script_tag(name:"creation_date", value:"2016-12-02 16:53:48 +0530 (Fri, 02 Dec 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Disk Savvy Enterprise Server Version Detection");
  script_tag(name: "summary" , value: "Detection of installed version of
  Disk Savvy Enterprise Server.

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
install = "";
sndReq = "";
rcvRes = "";
savvyPort  = "";
savvyVer = "";

##Get Disk Pulse Enterprise server Port
savvyPort = get_http_port(default:80);
if(!savvyPort){
  exit(0);
}

## Send request and receive response
sndReq = http_get(item:"/login", port:savvyPort);
rcvRes = http_keepalive_send_recv(port:savvyPort, data:sndReq);

## Confirm the server from response
if("Disk Savvy Enterprise Login" >< rcvRes &&
   ">User Name" >< rcvRes && ">Password" >< rcvRes)
{
  install = "/";
  savvyVer = eregmatch(pattern:">Disk Savvy Enterprise v([0-9.]+)", string:rcvRes);
  if(savvyVer[1]){
    savvyVer = savvyVer[1];
  } else {
    savvyVer = "Unknown";
  }

  ##Set the KB
  set_kb_item(name:"DiskSavvy/Enterprise/Server/installed", value:TRUE);

  ## build cpe and store it as host_detail
  ## Created new cpe
  cpe = build_cpe(value:savvyVer, exp:"([0-9.]+)", base:"cpe:/a:disksavvy:disksavvy_enterprise_web_server:");
  if(isnull(cpe))
    cpe = "cpe:/a:disksavvy:disksavvy_enterprise_web_server";

  ##Register Product and Build Report
  register_product(cpe:cpe, location:install, port:savvyPort);
  log_message(data: build_detection_report(app: "Disk Savvy Enterprise Server",
                                           version:savvyVer,
                                           install:install,
                                           cpe:cpe,
                                           concluded:savvyVer),
                                           port:savvyPort);
  exit(0);
}
exit(0);
