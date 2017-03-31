###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bigtree_detect.nasl 5329 2017-02-17 12:25:45Z mime $
#
# Bigtree Remote Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.807791");
  script_version("$Revision: 5329 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-02-17 13:25:45 +0100 (Fri, 17 Feb 2017) $");
  script_tag(name:"creation_date", value:"2016-04-18 12:45:32 +0530 (Mon, 18 Apr 2016)");
  script_name("Bigtree Remote Version Detection");

  script_tag(name : "summary" , value : "Detection of installed version
  of Bigtree.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_summary("Check for the presence of Bigtree");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

## Variable Initialization
sndReq = "";
rcvRes = "";
bigPort = "";
bigVer = "";
url = "";

##Get HTTP Port
if(!bigPort = get_http_port(default:80)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:bigPort)){
  exit(0);
}

##Iterate over possible paths
foreach dir (make_list_unique("/", "/BigTree", "/cms", "/bigtree", cgi_dirs(port:bigPort)))
{
  install = dir;
  if(dir == "/"){
    dir = "";
  }

  urls = make_list( dir + "/site/index.php/admin/login/", dir + "/admin/login/" );

  foreach url ( urls )
  {

    ## Send and receive response
    sndReq = http_get(item:url, port:bigPort);
    rcvRes = http_send_recv(port:bigPort, data:sndReq);

    ## Confirm the application
    if( rcvRes && ( "<title>BigTree Site Login</title>" >< rcvRes || "<title>Trees of All Sizes Login</title>") &&
                  "<label>Password</label>" >< rcvRes)
    {
      ## Grep for the version
      version = eregmatch(pattern:'Version ([0-9.]+)', string:rcvRes);
      if(version[1]){
        bigVer = version[1];
      }
      else{
        bigVer = "Unknown";
      }

      ## Set the KB
      set_kb_item(name:"BigTree/Installed", value:TRUE);

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:bigVer, exp:"^([0-9.]+)", base:"cpe:/a:bigtree:bigtree:");
      if(!cpe)
        cpe= "cpe:/a:bigtree:bigtree";

      register_product(cpe:cpe, location:install, port:bigPort);

      log_message(data: build_detection_report(app: "BigTree",
                                               version: bigVer,
                                               install: install,
                                               cpe: cpe,
                                               concluded: bigVer),
                                               port: bigPort);

    }
  }
}
