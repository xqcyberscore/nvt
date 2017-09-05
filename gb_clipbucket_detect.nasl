###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clipbucket_detect.nasl 7052 2017-09-04 11:50:51Z teissa $
#
# ClipBucket Remote Version Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809038");
  script_version("$Revision: 7052 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-09-04 13:50:51 +0200 (Mon, 04 Sep 2017) $");
  script_tag(name:"creation_date", value:"2016-09-08 11:15:03 +0530 (Thu, 08 Sep 2016)");
  script_name("ClipBucket Remote Version Detection");
  script_tag(name : "summary" , value : "Detection of installed version of
  ClipBucket.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

## Variable initialization
clipPort = 0;
install = "";
sndReq = "";
rcvRes = "";
version = "";

##Get HTTP Port
if(!clipPort = get_http_port(default:80)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:clipPort)){
  exit(0);
}

##Iterate over possible paths
foreach dir(make_list_unique("/", "/clipbucket", "/clipbucket/upload", "/clipbucket/Upload", "/clips", cgi_dirs(port:clipPort))) 
{

  install = dir;
  if( dir == "/" ) dir = "";

  ## Send and receive response
  sndReq = http_get(item:string(dir,"/admin_area/login.php"),  port:clipPort);
  rcvRes = http_keepalive_send_recv(port:clipPort, data:sndReq);
  
  ## Confirm the application
  if('ClipBucket Copyright' >< rcvRes && ('>Sign in with your Clipbucket Account' >< rcvRes || '>Username' >< rcvRes) &&
     (rcvRes =~ "<title>Admin Login - ClipBucket.*</title>" || "Arslan Hassan" >< rcvRes)) 
  {
    version = "unknown";

    ## Grep for the version
    ver = eregmatch(pattern:'<title>Admin Login - ClipBucket v([0-9A-Z. ]+)</title>', string:rcvRes);
    if(ver[1]) version = ver[1];
    
    ## Replacing with dot is space comes in version
    version = ereg_replace(pattern:" ", string:version, replace: ".");

    ## Set the KB value
    set_kb_item(name:"clipbucket/Installed", value:TRUE);

    ## build cpe and store it as host_detail
    cpe = build_cpe(value:version, exp:"^([0-9A-Z. ]+)", base:"cpe:/a:clipbucket_project:clipbucket:");
    if(!cpe){
      cpe = "cpe:/a:clipbucket_project:clipbucket";
    }

    register_product(cpe:cpe, location:install, port:clipPort);

    log_message( data:build_detection_report( app:"ClipBucket",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version),
                                              port:clipPort);
  }
}

exit(0);
