###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_liferay_detect.nasl 5499 2017-03-06 13:06:09Z teissa $
#
# Liferay Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.808730");
  script_version("$Revision: 5499 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-06 14:06:09 +0100 (Mon, 06 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-08-01 13:52:04 +0530 (Mon, 01 Aug 2016)");
  script_name("Liferay Version Detection");
  script_tag(name : "summary" , value : "Detection of installed version of
  Liferay.

  This script sends HTTP GET request and try to ensure the presence of Liferay
  from the response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

##Variable Initialisation
life_port = 0;
url = "";
sndReq = "";
rcvRes = "";

##Get HTTP Port
life_port = get_http_port(default:8080);
if(!life_port){
  exit(0);
}

##Iterate over possible paths
foreach dir(make_list_unique("/", "/Liferay", cgi_dirs(port:life_port)))
{

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + '/web/guest';

  ##Send Request and Receive Response
  sndReq = http_get(item:url, port:life_port);
  rcvRes = http_send_recv(port:life_port, data:sndReq);

  ## Confirm the application
  if(rcvRes =~ "HTTP/1.. 200 OK" && "Liferay<" >< rcvRes &&
     rcvRes =~ "Powered By.*Liferay" && "> Email Address" ><rcvRes)
  {
    vers = eregmatch(pattern:"Liferay Portal Community Edition (([0-9.]+) ?([A-Z0-9]+)? ([A-Z0-9]+))", string:rcvRes);
    if(vers[1]){
      version = vers[1];
    }
    else{
      version ="Unknown";
    }

    version = ereg_replace( pattern:" ", replace:".", string:version);

    ## Set the KB
    set_kb_item(name:"www/" + life_port + "/Liferay", value:version);
    set_kb_item(name:"Liferay/Installed", value:TRUE);

    ## build cpe and store it as host_detail
    cpe = build_cpe(value:version, exp:"([0-9.A-Z]+)", base:"cpe:/a:liferay:liferay_portal:");
    if(!cpe)
      cpe= "cpe:/a:liferay:liferay_portal";

    register_product(cpe:cpe, location:install, port:life_port);

    log_message(data:build_detection_report(app:"Liferay",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:version),
                                            port:life_port);
    exit(0);
  }
}
exit(0);
