###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zenoss_serv_detect.nasl 6065 2017-05-04 09:03:08Z teissa $
#
# Zenoss Server Version Detection
#
# Authors:
# Rachana Shetty <srachan@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_summary = "This script detects the installed version of Zenoss Server
  and sets the result in KB.";

if(description)
{
  script_id(800988);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 6065 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-04 11:03:08 +0200 (Thu, 04 May 2017) $");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Zenoss Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800988";
SCRIPT_DESC = "Zenoss Server Version Detection";

## Get Http Ports
httpPort = get_http_port(default:8080);
if(!httpPort){
  httpPort = 8080;
}

## Check Port status
if(!get_port_state(httpPort)){
  exit(0);
}

## Send Request and Receive Response
sndReq = http_get(item:"/zport/acl_users/cookieAuthHelper/login_form",
                  port:httpPort);
rcvRes = http_keepalive_send_recv(port:httpPort, data:sndReq);

if(("Zenoss Login" >< rcvRes))
{
  zenVer = eregmatch(pattern:"<span>([0-9.]+)" ,string:rcvRes);
  if(zenVer[1] != NULL)
  {
    set_kb_item(name:"www/" + httpPort + "/Zenoss", value:zenVer[1]);
    log_message(data:"Zenoss Server version " + zenVer[1] + " was detected on the host");
      
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:zenVer[1], exp:"^([0-9.]+)", base:"cpe:/a:zenoss:zenoss:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    exit(0);
  }
}
