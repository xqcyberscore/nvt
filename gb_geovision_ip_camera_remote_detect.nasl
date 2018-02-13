###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_geovision_ip_camera_remote_detect.nasl 8745 2018-02-09 14:30:40Z santu $
#
# Geovision Inc. IP Camera Remote Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.812758");
  script_version("$Revision: 8745 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-02-09 15:30:40 +0100 (Fri, 09 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-02-08 17:51:20 +0530 (Thu, 08 Feb 2018)");
  script_name("Geovision Inc. IP Camera Remote Detection");

  script_tag(name:"summary", value:"Detection of running version of Geovision
  Inc. IP Camera.
  
  This script sends HTTP GET request and try to ensure the presence of
  Geovision Inc. IP Camera.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

geoPort = 0;
rcvRes = "";
sndReq = "";
version = "";

if(!geoPort = get_http_port(default:80)){
  exit(0);
}

sndReq = http_get(item:"/ssi.cgi/Login.htm", port:geoPort);
rcvRes = http_keepalive_send_recv(port:geoPort, data:sndReq);

if("<TITLE>GeoVision Inc. - IP Camera</TITLE>" >< rcvRes &&
   rcvRes =~ "HTTP/1.. 200 OK")
{
  version = "Unknown";

  set_kb_item(name:"GeoVisionIP/Camera/Detected", value:TRUE);

  cpe = "cpe:/h:geovision:geovisionip_camera";

  register_product(cpe:cpe, location:"/", port:geoPort);

  log_message(data:build_detection_report(app:"GeoVision IP Camera",
                                          version:version,
                                          install:"/",
                                          cpe:cpe,
                                          concluded:version),
                                          port:geoPort);
  exit(0);
}
exit(0);
