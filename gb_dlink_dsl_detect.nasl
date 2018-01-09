###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dsl_detect.nasl 8325 2018-01-08 15:02:04Z cfischer $
#
# Dlink DSL Devices Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.812377");
  script_version("$Revision: 8325 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-01-08 16:02:04 +0100 (Mon, 08 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-03 16:00:40 +0530 (Wed, 03 Jan 2018)");
  script_name("Dlink DSL Devices Detection");

  script_tag(name:"summary", value:"Detection of Dlink DSL Devices.

  The script sends a connection request to the server and attempts to
  determine if the remote host is a Dlink DSL device from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("micro_httpd/banner");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

dir = "";
install = "";
dlinkPort = 0;
sndReq = "";
rcvRes = "";
dlinkVer = "";

if(!dlinkPort = get_http_port(default:80)){
  exit(0);
}

banner = get_http_banner(port:dlinkPort);
if(!banner){
  exit(0);
}

if("Server: micro_httpd" >< banner && 'WWW-Authenticate: Basic realm="DSL-' >< banner)
{
  dlinkVer = "Unknown";

  set_kb_item(name:"host_is_dlink_dsl", value:TRUE);

  model = eregmatch(pattern:'"DSL-([0-9A-Z]+)"', string:banner);
  if(model[1])
  {
    set_kb_item(name:"Dlink/DSL/model", value:model[1]);
    Model = model[1];
  } else {
    Model = "Unknown";
  }

  cpe = "cpe:/h:dlink:dsl-";

  register_product(cpe:cpe, location:dlinkPort + '/tcp', port:dlinkPort);

  log_message(data: build_detection_report(app:"Dlink DSL" , version:dlinkVer, install:dlinkPort + '/tcp', cpe:cpe,
              concluded:"DLink DSL Device Version:" + dlinkVer + ", Model:" + Model),
              port:dlinkPort);
  exit(0);
}
exit(0);
