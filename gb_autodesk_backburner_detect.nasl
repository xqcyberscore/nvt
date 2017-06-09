###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_autodesk_backburner_detect.nasl 5351 2017-02-20 08:03:12Z mwiegand $
#
# Autodesk Backburner Detection
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.808171");
  script_version("$Revision: 5351 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 09:03:12 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2016-08-23 15:56:59 +0530 (Tue, 23 Aug 2016)");
  script_name("Autodesk Backburner Detection");
  script_tag(name:"summary", value:"Detection of installed version of
  Autodesk Backburner.  

  This script sends HTTP GET request and try to fetch the version of
  Autodesk Backburner from the response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_summary("Get the version of Autodesk Backburner.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
dir = "";
back_port = 0;
rcvRes = "";

##Get backburner Port
if(!back_port = get_http_port(default:80)){
  exit(0);
}

##Iterate over possible paths
foreach dir(make_list_unique("/", "/Backburner/", cgi_dirs(port:back_port)))
{
  install = dir;

  ## Send and receive response
  sndReq = http_get(item: dir, port:back_port);
  rcvRes = http_send_recv(port:back_port, data:sndReq);

  ##Confirm application
  if(rcvRes =~ '<title>Autodesk Backburner Monitor .*</title>' && 'HTTP/1.1 200 OK' >< rcvRes) 
  {
    version = eregmatch(pattern:'<title>Autodesk Backburner Monitor ([0-9.]+).*Build ([0-9]+)', string:rcvRes);

    if(!version[1] && !version[2]){ 
      version = "unknown";
    }else{
    version  = version[1] + "." + version[2];
    }
    
    ## Set the KB value
    set_kb_item(name:"Autodesk/Backburner/Ver", value:TRUE);

    ## build cpe and store it as host_detail
    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:autodesk:autodesk_backburner:");
    if(isnull(cpe)){
      cpe = "cpe:/a:autodesk:autodesk_backburner";
    }

    register_product(cpe:cpe, location:install, port:back_port);

    log_message( data:build_detection_report( app:"Autodesk Backburner",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version),
                                              port:back_port);
    exit(0);
  }
}
exit(0);
