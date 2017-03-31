###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_easy_file_sharing_web_server_detect.nasl 5390 2017-02-21 18:39:27Z mime $
#
# Easy File Sharing Web Server Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.806517");
  script_version("$Revision: 5390 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-02-21 19:39:27 +0100 (Tue, 21 Feb 2017) $");
  script_tag(name:"creation_date", value:"2015-11-05 11:28:37 +0530 (Thu, 05 Nov 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Easy File Sharing Web Server Version Detection");

  script_tag(name: "summary" , value: "Detection of installed version of
  Easy File Sharing Web Server.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");
  script_summary("Set Version of Easy File Sharing Web Server in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("EasyFileSharingWebServer/banner");
  script_require_ports("Services/www", 80);
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
banner = "";
easyPort  = "";
easyVer = "";

##Get HP SiteScope Port
easyPort = get_http_port(default:80);
if(!easyPort){
  exit(0);
}

## Check the port status
if(!get_port_state(easyPort)){
  exit(0);
}

banner = get_http_banner(port:easyPort);

## Confirm the server from banner
if(banner && "Server: Easy File Sharing Web Server" >< banner)
{
  easyVer = eregmatch(pattern:"Server: Easy File Sharing Web Server v([0-9.]+)", string:banner);
  if(easyVer[1]){
    easyVer = easyVer[1];
  } else {
    easyVer = "Unknown";
  }

  ##Set the KB
  set_kb_item(name:"www/" + easyPort + "/", value:easyVer);
  set_kb_item(name:" Easy/File/Sharing/WebServer/installed", value:TRUE);

  ## build cpe and store it as host_detail
  cpe = build_cpe(value: easyVer, exp:"([0-9.]+)", base:"cpe:/a:efssoft:easy_file_sharing_web_server:");
  if(isnull(cpe))
    cpe = "cpe:/a:efssoft:easy_file_sharing_web_server";

  ##Register Product and Build Report
  register_product(cpe:cpe, location:"/", port:easyPort);
  log_message(data: build_detection_report(app: "Easy File Sharing Web Server",
                                           version:easyVer,
                                           install:"/",
                                           cpe:cpe,
                                           concluded:easyVer),
                                           port:easyPort);
  exit(0);
}
