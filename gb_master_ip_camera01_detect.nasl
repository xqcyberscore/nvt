###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_master_ip_camera01_detect.nasl 8539 2018-01-25 14:37:09Z gveerendra $
#
# MASTER IP CAMERA 01 Remote Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.812657");
  script_version("$Revision: 8539 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 15:37:09 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-22 12:19:43 +0530 (Mon, 22 Jan 2018)");
  script_name("MASTER IP CAMERA 01 Remote Detection");

  script_tag(name:"summary", value:"Detection of running version of
  MASTER IP CAMERA 01.
  
  This script sends HTTP GET request and try to ensure the presence of
  MASTER IP CAMERA 01.");

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

ipPort = 0;
rcvRes = "";
sndReq = "";
version = "";

if(!ipPort = get_http_port(default:80)){
  exit(0);
}

sndReq = http_get(item:"/web/index.html", port:ipPort);
rcvRes = http_keepalive_send_recv(port:ipPort, data:sndReq);

if(rcvRes =~ "Server:.thttpd" && ("<title>ipCAM<" >< rcvRes || "<title>Camera<" >< rcvRes) &&
   "cgi-bin/hi3510" >< rcvRes && ">OCX" >< rcvRes)
{

  version = "unknown";

  ## Set the KB value
  set_kb_item(name:"MasterIP/Camera/Detected", value:TRUE);

  ## creating new cpe for this product
  ## build cpe and store it as host_detail
  cpe = "cpe:/h:masterip:masterip_camera";

  register_product(cpe:cpe, location:"/", port:ipPort);

  log_message(data:build_detection_report(app:"MasterIP Camera 01",
                                          version:version,
                                          install:"/",
                                          cpe:cpe,
                                          concluded:version),
                                          port:ipPort);
  exit(0);
}
exit(0);
