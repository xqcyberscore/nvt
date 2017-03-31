###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_diskboss_enterprise_detect.nasl 4695 2016-12-07 07:30:56Z mime $
#
# DiskBoss Enterprise Version Detection
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.140094");
  script_version("$Revision: 4695 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-12-07 08:30:56 +0100 (Wed, 07 Dec 2016) $");
  script_tag(name:"creation_date", value:"2016-12-06 16:11:25 +0530 (Tue, 06 Dec 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("DiskBoss Enterprise Version Detection");

  script_tag(name: "summary" , value: "Detection of installed version of
  DiskBoss Enterprise.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_summary("Get the Version of DiskBoss Enterprise");
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
dbossPort  = "";
dbossVer = "";

##Get Disk Pulse Enterprise server Port
dbossPort = get_http_port(default:8080);
if(!dbossPort){
  exit(0);
}

## Send request and receive response
sndReq = http_get(item:"/login", port:dbossPort);
rcvRes = http_keepalive_send_recv(port:dbossPort, data:sndReq);

## Confirm the server from response
if(">DiskBoss Enterprise" >< rcvRes &&
   ">User Name" >< rcvRes && ">Password" >< rcvRes)
{
  dbossVer = eregmatch(pattern:">DiskBoss Enterprise v([0-9.]+)", string:rcvRes);
  if(dbossVer[1]){
    dbossVer = dbossVer[1];
  } else {
    dbossVer = "Unknown";
  }

  ##Set the KB
  set_kb_item(name:"Disk/Boss/Enterprise/installed", value:TRUE);

  ## build cpe and store it as host_detail
  ## Created new cpe
  cpe = build_cpe(value:dbossVer, exp:"([0-9.]+)", base:"cpe:/a:dboss:diskboss_enterprise:");
  if(isnull(cpe))
    cpe = "cpe:/a:dboss:diskboss_enterprise";

  ##Register Product and Build Report
  register_product(cpe:cpe, location:"/", port:dbossPort);
  log_message(data: build_detection_report(app: "DiskBoss Enterprise",
                                           version:dbossVer,
                                           install:"/",
                                           cpe:cpe,
                                           concluded:dbossVer),
                                           port:dbossPort);
}
exit(0);

