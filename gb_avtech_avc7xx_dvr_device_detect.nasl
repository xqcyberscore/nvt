################################i###############################################
# OpenVAS Vulnerability Test
# $Id: gb_avtech_avc7xx_dvr_device_detect.nasl 10887 2018-08-10 12:05:12Z santu $
#
# AVTech AVC 7xx DVR Device Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.813817");
  script_version("$Revision: 10887 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:05:12 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-08-07 12:34:02 +0530 (Tue, 07 Aug 2018)");
  script_name("AVTech AVC 7xx DVR Device Detection");

  script_tag(name:"summary", value:"Detection of AVTech AVC 7xx DVR
  device.

  This script sends HTTP GET request and try to ensure the presence of
  AVTech AVC 787 DVR device from the response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"http://www.avtech.hk/english/products5_1_787.htm");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

avPort = get_http_port(default:80);
res = http_get_cache(port: avPort, item: "/");

if(res !~ "HTTP/1.. 200 OK" || "Server: SQ-WEBCAM" >!< res ||
   res !~ "<title>.*VIDEO WEB SERVER.*</title>" || res !~ "IP Surv(e)?illance"){
  exit(0);
}

avVer = "Unknown";
set_kb_item(name:"AVTech/AVC7xx/DVR/Device/Detected", value:TRUE);

## Created new cpe
cpe = "cpe:/o:avtech:avc7xx_dvr";

register_product(cpe:cpe, location:"/", port:avPort);

log_message(data: build_detection_report(app: "Avtech AVC 7xx DVR",
                                           version: avVer,
                                           install: "/",
                                           cpe: cpe,
                                           concluded: avVer),
                                           port: avPort);
exit(0);
