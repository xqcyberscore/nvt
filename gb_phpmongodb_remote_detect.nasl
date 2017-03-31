###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmongodb_remote_detect.nasl 3175 2016-04-27 05:25:38Z antu123 $
#
# PHPmongoDB Remote Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.807553");
  script_version("$Revision: 3175 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-04-27 07:25:38 +0200 (Wed, 27 Apr 2016) $");
  script_tag(name:"creation_date", value:"2016-04-25 12:39:59 +0530 (Mon, 25 Apr 2016)");
  script_name("PHPmongoDB Remote Version Detection");

  script_tag(name : "summary" , value : "Detection of installed version of
  PHPmongoDB.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_summary("Check for the presence of PHPmongoDB.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## 
sndReq = "";
rcvRes = "";
phpmongoVer = "";
mongoPort = "";

##Get HTTP Port
if(!mongoPort = get_http_port(default:80)){
  exit(0);
}

## Checking host support php
if(!can_host_php(port:mongoPort)){
  exit(0);
}

foreach dir (make_list_unique("/", "/phpmongodb", "/PHPmongoDB", cgi_dirs(port:mongoPort)))
{
  install = dir;
  if( dir == "/" ) dir = "";

  ##Construct url
  url =  dir + "/index.php";
  
  ##Send Request and Receive Response
  sndReq = http_get(item:url, port:mongoPort);
  rcvRes = http_keepalive_send_recv(port:mongoPort, data:sndReq, bodyonly:TRUE);

  #Confirm application
  if('<title>PHPmongoDB </title>' ><  rcvRes && 'content="mongoDB' >< rcvRes &&
     rcvRes =~ 'copy.*PHPmongoDB.org' && '>Sign In' >< rcvRes)
  {
    ## Grep for the version, try to read README.md file
    url = dir + '/README.md';
    
    ##Send Request and Receive Response
    sndReq = http_get(item:url, port:mongoPort);
    rcvRes = http_keepalive_send_recv(port:mongoPort, data:sndReq, bodyonly:TRUE);

    version = eregmatch(pattern:'version ([0-9.]+)', string:rcvRes);
    if(version[1]){
      phpmongoVer = version[1];
    } else {
      phpmongoVer = "Unknown";
    }

    set_kb_item(name:"PHPmongoDB/Installed", value:TRUE);

    ## build cpe and store it as host_detail
    ## cpe is not available. so created new
    cpe = build_cpe(value:phpmongoVer, exp:"^([0-9.]+)", base:"cpe:/a:php:mongodb:");
    if(!cpe)
      cpe = "cpe:/a:php:mongodb";

    register_product(cpe:cpe, location:install, port:mongoPort);

    log_message(data: build_detection_report(app: "PHPmongoDB",
                                             version: phpmongoVer,
                                             install: install,
                                             cpe: cpe,
                                             concluded: phpmongoVer),
                                             port: mongoPort);
  }
}
