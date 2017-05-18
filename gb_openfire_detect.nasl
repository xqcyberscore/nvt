###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openfire_detect.nasl 6032 2017-04-26 09:02:50Z teissa $
#
# OpenFire Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800353");
  script_version("$Revision: 6032 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-26 11:02:50 +0200 (Wed, 26 Apr 2017) $");
  script_tag(name:"creation_date", value:"2009-02-11 16:51:00 +0100 (Wed, 11 Feb 2009)");
  script_name("OpenFire Version Detection");

  script_tag(name : "summary" , value : "This script detects the installed
  version of OpenFire and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 9090);
  exit(0);
}


include("http_func.inc");
include("cpe.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
sndReq = "";
rcvRes = "";
firePort = "";
fireVer = "";

# Check for default port 9090
firePort = get_http_port(default:9090);

sndReq = http_get(item:string("/login.jsp"), port:firePort);
rcvRes = http_keepalive_send_recv(port:firePort, data:sndReq);
if(rcvRes == NULL){
  exit(0);
}

if("Openfire Admin Console" >< rcvRes)
{
  ver = eregmatch(pattern:"Openfire, Version: ([0-9.]+)", string:rcvRes);
  if(ver[1]){
    fireVer = ver[1];
  } else {
    fireVer = "Unknown";
  }

  set_kb_item(name:"www/" + firePort + "/Openfire", value:fireVer);
  set_kb_item(name:"OpenFire/Installed", value:TRUE);
  log_message(data:"OpenFire version " + fireVer +
                 " was detected on the host");

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:fireVer, exp:"^([0-9.]+)", base:"cpe:/a:igniterealtime:openfire:");
  if(!cpe)
      cpe = "cpe:/a:igniterealtime:openfire";
  register_product(cpe:cpe, location:"/", port:firePort);

  log_message(data: build_detection_report(app: "OpenFire",
                                           version: fireVer,
                                           install: "/",
                                           cpe: cpe,
                                           concluded: fireVer),
                                           port: firePort);
}
