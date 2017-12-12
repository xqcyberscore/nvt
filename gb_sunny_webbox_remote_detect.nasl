###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sunny_webbox_remote_detect.nasl 8078 2017-12-11 14:28:55Z cfischer $
#
# Sunny WebBox Remote Version Detection
#
# Authors:
# Rinu Kuriaksoe <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.808203");
  script_version("$Revision: 8078 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-11 15:28:55 +0100 (Mon, 11 Dec 2017) $");
  script_tag(name:"creation_date", value:"2016-05-24 10:37:42 +0530 (Tue, 24 May 2016)");
  script_name("Sunny WebBox Remote Version Detection");

  script_tag(name : "summary" , value : "Detection of installed version of
  SMA Solar Technology AG Sunny WebBox.

  This script check the presence of SMA Solar Technology AG Sunny WebBox from the 
  banner and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("WebBox/banner");

  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
banner = "";
sunnyVer = 0;
sunnyPort = "";

## Get HTTP Port
sunnyPort = get_http_port(default:8080);

## Get banner
banner = get_http_banner(port:sunnyPort);

#Confirm application
if(banner && "Server: WebBox" >< banner)
{
  sunnyVer = "Unknown";

  ## Set kb
  set_kb_item(name:"Sunny/WebBox/Installed", value:TRUE);

  ## build cpe and store it as host_detail
  cpe = "cpe:/o:sma_solar_technology_ag:webbox_firmware";

  register_product(cpe:cpe, location:"/", port:sunnyPort);

  log_message(data: build_detection_report(app: "SMA Solar Sunny WebBox",
                                           version: sunnyVer,
                                           install: "/",
                                           cpe: cpe,
                                           concluded: sunnyVer),
                                           port: sunnyPort);
}
