###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trendmicro_smart_protection_server_detect.nasl 7586 2017-10-26 15:47:05Z cfischer $
#
# Trend Micro Smart Protection Server Remote Version Detection
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811915");
  script_version("$Revision: 7586 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 17:47:05 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-10-05 17:44:54 +0530 (Thu, 05 Oct 2017)");
  script_name("Trend Micro Smart Protection Server Remote Version Detection");

  script_tag(name : "summary" , value : "Detection of installed version
  of Trend Micro Smart Protection Server.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 4343);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
sndReq = "";
rcvRes = "";
tspsPort = 0;
pfsVer = "";

tspsPort = get_http_port(default:4343);
if(!can_host_php(port:tspsPort)) exit(0);

rcvRes = http_get_cache(item:"/index.php", port:tspsPort);

## Confirm application
if('Trend Micro Smart Protection Server' >< rcvRes &&
   'Please type your user name and password to access the product console.' >< rcvRes)
{
  vers = "Unknown";

  ## Set the KB value
  set_kb_item(name:"trendmicro/SPS/Installed", value:TRUE);

  ## Send request and receive response
  sndReq = http_get( item:"/help/en_US.UTF-8/Introduction.html", port:tspsPort );
  rcvRes = http_keepalive_send_recv( port:tspsPort, data:sndReq );

  ## Grep version
  vers = eregmatch( pattern:'<title>Trend Micro.* Smart Protection Server.* ([0-9.]+) Online Help<', string:rcvRes);
  if(vers[1]){
    vers = vers[1];
  }

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:trendmicro:smart_protection_server:");
  if(!cpe)
     cpe = 'cpe:/a:trendmicro:smart_protection_server';

  register_product(cpe:cpe, location:"/", port:tspsPort);
  log_message(data: build_detection_report(app: "Trend Micro Smart Protection Server",
                                           version: vers,
                                           install: "/",
                                           cpe: cpe,
                                           concluded: vers),
                                           port: tspsPort);
}
