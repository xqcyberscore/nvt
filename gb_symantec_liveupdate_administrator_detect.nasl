###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_liveupdate_administrator_detect.nasl 6032 2017-04-26 09:02:50Z teissa $
#
# Symantec LiveUpdate Administrator Version Detection
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

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.804358";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6032 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-26 11:02:50 +0200 (Wed, 26 Apr 2017) $");
  script_tag(name:"creation_date", value:"2014-04-03 12:20:29 +0530 (Thu, 03 Apr 2014)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Symantec LiveUpdate Administrator Version Detection");

  tag_summary =
"Detection of installed version of Symantec LiveUpdate Administrator.

This script sends HTTP GET request and try to get the version from the
response, and sets the result in KB.";


  script_tag(name : "summary" , value : tag_summary);

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 7070);
  exit(0);
}


include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
luaPort = "";
luaVer = "";
sndReq = "";
rcvRes = "";

## Get http port
luaPort = get_http_port(default:7070);
if(!luaPort){
  luaPort = 7070;
}

## Check the port status
if(!get_port_state(luaPort)){
  exit(0);
}

sndReq = http_get(item: "/lua/onlinehelp/LUHelp0002.html", port:luaPort);
rcvRes = http_send_recv(port:luaPort, data:sndReq, bodyonly:TRUE);

##Confirm the application
if(rcvRes && "LiveUpdate Administrator<" >< rcvRes)
{
  sndReq = http_get(item:  "/lua/logon.do", port:luaPort);
  rcvRes = http_send_recv(port:luaPort, data:sndReq, bodyonly:TRUE);

  if(rcvRes && "lua_title" >< rcvRes && "Symantec Corporation" >< rcvRes)
  {
    ## try to get version
    luaVer = eregmatch( string:rcvRes, pattern:"Version:.([0-9.]+)", icase:TRUE);

    if(luaVer[1] != NULL)
    {
      set_kb_item(name:"Symantec/LUA/Version", value:luaVer[1]);

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:luaVer[1], exp:"^([0-9.]+)", base:"cpe:/a:symantec:liveupdate_administrator:");
      if(!cpe)
        cpe="cpe:/a:symantec:liveupdate_administrator";

      register_product(cpe:cpe, location:"/lua", nvt:SCRIPT_OID, port:luaPort);

      log_message(data: build_detection_report(app: "Symantec LiveUpdate Administrator",
                                               version: luaVer[1],
                                               install: "/lua",
                                               cpe: cpe,
                                               concluded: luaVer[1]), port: luaPort);
      exit(0);
    }
  }
}
