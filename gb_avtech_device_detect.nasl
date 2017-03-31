###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avtech_device_detect.nasl 5390 2017-02-21 18:39:27Z mime $
#
# AVTECH Device Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.809066");
  script_version("$Revision: 5390 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-02-21 19:39:27 +0100 (Tue, 21 Feb 2017) $");
  script_tag(name:"creation_date", value:"2016-10-18 11:30:44 +0530 (Tue, 18 Oct 2016)");
  script_name("AVTECH Device Detection");

  script_tag(name : "summary" , value : "Detection of AVTECH Device.

  This script sends HTTP GET request and try to ensure the presence of
  AVTECH Device from the response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_summary("Check for the presence of AVTECH Device");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Avtech/banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");


## Variable initialization
avPort = 0;
banner = "";
avVer = "";

##Get HTTP Port
avPort = get_http_port(default:8080);

## Get banner
banner = get_http_banner(port:avPort);

## Confirm the application
if(banner !~ "HTTP/1.. 200 OK" || banner !~ "Server:.*Avtech"){
  exit(0);
}

avVer = "Unknown";

## Set kb
set_kb_item(name:"AVTECH/Device/Installed", value:TRUE);

## Created new cpe
## build cpe and store it as host_detail
cpe = "cpe:/o:avtech:avtech_device";

register_product(cpe:cpe, location:"/", port:avPort);

log_message(data: build_detection_report(app: "AVTECH Device",
                                           version: avVer,
                                           install: "/",
                                           cpe: cpe,
                                           concluded: avVer),
                                           port: avPort);
exit(0);
