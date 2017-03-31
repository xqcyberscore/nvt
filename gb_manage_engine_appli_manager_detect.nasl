###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manage_engine_appli_manager_detect.nasl 4623 2016-11-25 06:56:52Z cfi $
#
# ManageEngine Applications Manager Detection
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.808054");
  script_version("$Revision: 4623 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-11-25 07:56:52 +0100 (Fri, 25 Nov 2016) $");
  script_tag(name:"creation_date", value:"2016-05-23 10:45:33 +0530 (Mon, 23 May 2016)");
  script_name("ManageEngine Applications Manager Detection");

  script_tag(name : "summary" , value : "Detection of installed version of
  ManageEngine Applications Manager.

  This script check the presence of ManageEngine Applications Manager from the
  banner and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_summary("Check the presence of ManageEngine Applications Manager");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
manageVer ="";
managePort = 0;
install = "";
sndReq = "";
rcvRes = "";

## Get HTTP Port
if(!managePort = get_http_port(default:80)){
  exit(0);
}

##Iterate over possible paths
foreach dir(make_list_unique( "/", "/manageengine", cgi_dirs(port:managePort)))
{
  install = dir;
  if( dir == "/" ) dir = "";

  ##Construct url
  url = dir + "/index.do";
    
  ##Send Request and Receive Response
  sndReq = http_get(item:url, port:managePort);
  rcvRes = http_send_recv(port:managePort, data:sndReq);

  ## Confirm the application
  if( rcvRes =~ "HTTP/1.. 200" && "manageengine" >< rcvRes &&
    ('<title>Applications Performance Monitoring Software</title>' >< rcvRes))
  {
    manageVer = "Unknown";

    ## Set the KB value
    set_kb_item( name:"ManageEngine/Applications/Manager/Installed", value:TRUE );

    ## build cpe and store it as host_detail
    cpe = "cpe:/a:manageengine:applications_manager";

    register_product(cpe:cpe, location:install, port:managePort);

    log_message(data:build_detection_report(app:"ManageEngine Applications Manager",
                                            version:manageVer,
                                            install:install,
                                            cpe:cpe,
                                            concluded:manageVer),
                                            port:managePort);
  }   
  exit(0);
}
