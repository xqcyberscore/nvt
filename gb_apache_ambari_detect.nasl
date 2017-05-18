################################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_ambari_detect.nasl 5803 2017-03-31 05:06:31Z ckuerste $
#
# Apache Ambari Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.808648");
  script_version("$Revision: 5803 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-31 07:06:31 +0200 (Fri, 31 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-08-09 18:35:29 +0530 (Tue, 09 Aug 2016)");
  script_name("Apache Ambari Detection");
  script_tag(name : "summary" , value : "Detection of installed version of
  Apache Ambari.

  This script sends HTTP GET request and try to get the version of Apache
  Ambari from the response, and sets the result in KB .");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 8080);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

##Variable Initialisation
amb_Port = 0;
url = "";
sndReq = "";
rcvRes = "";

##Get HTTP Port
amb_Port = get_http_port(default:8080);
if(!amb_Port){
  exit(0);
}

## Get host name or IP
host = http_host_name(port:amb_Port);
if(!host){
  exit(0);
}

## Construct url
url = '/javascripts/app.js';

# Send Request and Receive Response
req = 'GET '+url+' HTTP/1.1\r\n' +
      'Host: '+host+'\r\n' +
      'Accept-Encoding: gzip, deflate\r\n' +
      '\r\n';
rcvRes = http_keepalive_send_recv(port:amb_Port, data:req); 
  
## Confirm the application
if(rcvRes =~ "HTTP/1.. 200 OK" && "Ambari" >< rcvRes &&
   rcvRes =~ "Licensed under the Apache License")
{
  version = "unknown";

  vers = eregmatch(pattern:"App.version = '([0-9.]+)';", string:rcvRes);
  if(vers[1]){
    version = vers[1];
    set_kb_item(name: "Apache/Ambari/version", value: version);
  }
    
  ## Set the KB
  set_kb_item(name:"www/" + amb_Port + dir, value:version);
  set_kb_item(name:"Apache/Ambari/Installed", value:TRUE);

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:version, exp:"([0-9.]+)", base:"cpe:/a:apache:ambari:");
  if(!cpe)
    cpe= "cpe:/a:apache:ambari";

  register_product(cpe:cpe, location:"/", port:amb_Port);

  log_message(data:build_detection_report(app:"Apache Ambari",
                                          version:version,
                                          install:"/",
                                          cpe:cpe,
                                          concluded:vers[0]),
                                          port:amb_Port);
  exit(0);
}
exit(0);
