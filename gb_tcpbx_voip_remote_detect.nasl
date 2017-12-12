###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tcpbx_voip_remote_detect.nasl 8078 2017-12-11 14:28:55Z cfischer $
#
# tcPbX VoIP Remote Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.809008");
  script_version("$Revision: 8078 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-11 15:28:55 +0100 (Mon, 11 Dec 2017) $");
  script_tag(name:"creation_date", value:"2016-08-23 15:56:59 +0530 (Tue, 23 Aug 2016)");
  script_name("tcPbX VoIP Remote Detection");
  script_tag(name:"summary", value:"Detection of installed version of 
  tcPbX VoIP.

  This script sends HTTP GET request and try to ensure the presence of
  tcPbX VoIP.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
voipPort = 0;
rcvRes = "";
sndReq = "";
version = "";
cpe = "";

##Get HTTP Port
if(!voipPort = get_http_port(default:80)){
  exit(0);
}

## Send and receive response
sndReq = http_get(item:"/tcpbx/", port:voipPort);
rcvRes = http_send_recv(port:voipPort, data:sndReq);

##Confirm application
if('<title>tcPbX</title>' >< rcvRes && '>www.tcpbx.org' >< rcvRes) 
{
  version = "unknown";

  ## Set the KB value
  set_kb_item(name:"tcPbX/Installed", value:TRUE);

  ## creating new cpe for this product
  ## build cpe and store it as host_detail
  cpe = "cpe:/a:tcpbx:tcpbx_voip";

  register_product(cpe:cpe, location:"/tcpbx", port:voipPort);

  log_message(data:build_detection_report(app:"tcPbX",
                                          version:version,
                                          install:"/tcpbx",
                                          cpe:cpe,
                                          concluded:version),
                                          port:voipPort);
}
exit(0);
