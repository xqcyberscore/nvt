###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_barracuda_drive_detect.nasl 7000 2017-08-24 11:51:46Z teissa $
#
# BarracudaDrive Version Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804608");
  script_version("$Revision: 7000 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-08-24 13:51:46 +0200 (Thu, 24 Aug 2017) $");
  script_tag(name:"creation_date", value:"2014-06-02 09:14:12 +0530 (Mon, 02 Jun 2014)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("BarracudaDrive Version Detection");

  tag_summary =
"Detection of BarracudaDrive.

This script sends HTTP GET request and try to get the version from the
response, and sets the result in KB.";


  script_tag(name : "summary" , value : tag_summary);

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
http_port = "";
bdVer = "";
bdReq = "";
bdRes = "";

## Get http port
http_port = get_http_port(default:80);
if(!http_port){
  exit(0);
}

## Check the port status
if(!get_port_state(http_port)){
  exit(0);
}

bdReq = http_get(item: "/rtl/about.lsp" , port:http_port);
bdRes = http_send_recv(port:http_port, data:bdReq);

##  Confirm the application
if(">BarracudaDrive" >< bdRes)
{
  bdVer = eregmatch(pattern:"(>Version|>BarracudaDrive|>BarracudaDrive.[v|V]ersion:).([0-9.]+)<", string:bdRes);

  if(bdVer[2])
  {
    set_kb_item(name:"www/" + http_port + "/BarracudaDrive", value:bdVer[2]);
    set_kb_item(name:"BarracudaDrive/Installed", value:TRUE);

    ## Build the CPE
    cpe = build_cpe(value:bdVer[2], exp:"^([0-9.]+)", base:"cpe:/a:barracudadrive:barracudadrive:");
    if(isnull(cpe))
      cpe = 'cpe:/a:barracudadrive:barracudadrive';

    ## Register the product
    register_product(cpe:cpe, location:http_port + '/tcp', port:http_port);

    log_message(data: build_detection_report(app:"BarracudaDrive",
                                           version:bdVer[2],
                                           install:http_port + '/tcp',
                                           cpe:cpe,
                                           concluded: bdVer[2]),
                                           port:http_port);
  }
}
