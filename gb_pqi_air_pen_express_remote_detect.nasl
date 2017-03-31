###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pqi_air_pen_express_remote_detect.nasl 3097 2016-04-18 13:33:30Z antu123 $
#
# PQI Air Pen Express Remote Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.807535");
  script_version("$Revision: 3097 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-04-18 15:33:30 +0200 (Mon, 18 Apr 2016) $");
  script_tag(name:"creation_date", value:"2016-02-18 10:58:19 +0530 (Thu, 18 Feb 2016)");
  script_name("PQI Air Pen Express Remote Version Detection");


  script_tag(name:"summary", value:"Detection of installed version
  of PQI Air Pen Express.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_summary("Check for the presence of PQI Air Pen Express");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variable initialization
cpe = "";
pqiPort = 0;
sndReq = "";
rcvRes = "";

##Get HTTP Port
if(!pqiPort = get_http_port(default:80)){
  exit(0);
}

##Send Request and Receive Response
sndReq = http_get(item:"/home.asp", port:pqiPort);
rcvRes = http_keepalive_send_recv(port:pqiPort, data:sndReq);

## Confirm the application
if( rcvRes && '<TITLE>Air Pen express' >< rcvRes )
{
  version = "unknown";

  ## Set the KB value
  set_kb_item(name:"www/" + pqiPort + "/PQI/Air/Pen/Express", value:version);
  set_kb_item(name:"PQI/Air/Pen/Express/Installed", value:TRUE);

  ## build cpe
  cpe= "cpe:/a:pqi:air:pen:express";

  ## Register product
  register_product( cpe:cpe, location:"/", port:pqiPort );

  log_message(data:build_detection_report(app:"PQI Air Pen express",
                                            version:version,
                                            install:"/",
                                            cpe:cpe),
                                            port:pqiPort);
}

exit(0);
