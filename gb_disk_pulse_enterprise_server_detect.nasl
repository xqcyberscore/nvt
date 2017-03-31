###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_disk_pulse_enterprise_server_detect.nasl 4311 2016-10-20 11:26:18Z antu123 $
#
# Disk Pulse Enterprise Server Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.809056");
  script_version("$Revision: 4311 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-10-20 13:26:18 +0200 (Thu, 20 Oct 2016) $");
  script_tag(name:"creation_date", value:"2016-10-05 16:17:52 +0530 (Wed, 05 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Disk Pulse Enterprise Server Version Detection");

  script_tag(name: "summary" , value: "Detection of installed version of
  Disk Pulse Enterprise Server.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_summary("Set Version of Disk Pulse Enterprise Server in KB");
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
diskPort  = "";
diskVer = "";

##Get Disk Pulse Enterprise server Port
diskPort = get_http_port(default:80);
if(!diskPort){
  exit(0);
}

## Send request and receive response
sndReq = http_get(item:"/login", port:diskPort);
rcvRes = http_keepalive_send_recv(port:diskPort, data:sndReq);

## Confirm the server from response
if("Disk Pulse Enterprise Login" >< rcvRes &&
   ">User Name" >< rcvRes && ">Password" >< rcvRes)
{
  diskVer = eregmatch(pattern:">Disk Pulse Enterprise v([0-9.]+)", string:rcvRes);
  if(diskVer[1]){
    diskVer = diskVer[1];
  } else {
    diskVer = "Unknown";
  }

  ##Set the KB
  set_kb_item(name:"DiskPulse/Enterprise/Server/installed", value:TRUE);

  ## build cpe and store it as host_detail
  ## Created new cpe
  cpe = build_cpe(value:diskVer, exp:"([0-9.]+)", base:"cpe:/a:diskpulse:diskpulse_enterprise_web_server:");
  if(isnull(cpe))
    cpe = "cpe:/a:diskpulse:diskpulse_enterprise_web_server";

  ##Register Product and Build Report
  register_product(cpe:cpe, location:"/", port:diskPort);
  log_message(data: build_detection_report(app: "Disk Pulse Enterprise Server",
                                           version:diskVer,
                                           install:"/",
                                           cpe:cpe,
                                           concluded:diskVer),
                                           port:diskPort);
  exit(0);
}
exit(0);
