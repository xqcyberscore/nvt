###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_brickcom_network_cameras_mult_vuln.nasl 7174 2017-09-18 11:48:08Z asteins $
#
# Brickcom Network Cameras Multiple Vulnerabilities
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808159");
  script_version("$Revision: 7174 $");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 13:48:08 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2016-06-10 17:32:08 +0530 (Fri, 10 Jun 2016)");
  script_name("Brickcom Network Cameras Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is running Brickcom Network Cameras
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP POST request and check
  whether it is able to login or not.");

  script_tag(name:"insight", value:"The flaws exist due to,
  - 'syslog.dump', 'configfile.dump' files are accessible without 
    authenication.
  - Credentials and other sensitive information are stored in plain text.
  - The usage of defaults Credentials like 'admin:admin', 'viewer:viewer',
    'rviewer:rviewer'.
  - An improper input validation for parameter 'action' to 
    'NotificationTest.cgi' script.
  - A Cross-site Request Forgery.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  access sensitive information stored in html page,to gain administartive access,
  also leads to cross-site scripting attcks and cross-site request forgery attacks.

  Impact Level: Application");

  script_tag(name:"affected", value:"For information on affected products and 
  firmware version refer the link mentioned in reference.");

  script_tag(name:"solution", value:"No solution or patch was made available for at least one year since disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/136693/OLSA-2015-12-12.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("Brickcom/banner");

  exit(0);
}


## The script code starts here

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

## Variable initialization
url = "";
bric_port = 0;
req = "";
res = "";

## Get HTTP Port
bric_port = get_http_port(default:8080);

##Confirm Brickcom Network Cameras.
banner = get_http_banner(port:bric_port);
if('Basic realm="Brickcom' >!< banner){
  exit(0);
}

## Get host name or IP
host = http_host_name(port:bric_port);
if(!host){
  exit(0);
}

##url
url = "/user_management_config.html";
userpasswds = make_list("admin:admin", "viewer:viewer", "rviewer:rviewer");

foreach userpass(userpasswds)
{
  userpass64 = base64(str: userpass); 
 
  ##Construct the attack request
  req =  'GET '+url+' HTTP/1.1\r\n' +
         'Host: ' +host+ '\r\n' + 
         'Authorization: Basic '+userpass64+'\r\n'+
         '\r\n';
  res =  http_send_recv(port:bric_port, data:req);

  ##Checking for the presence of hardcoded credentials.
  if('HTTP/1.1 200 Ok' >< res && 'Brickcom Corporation' >< res && 
     '<title>User Management</title>' >< res && '="viewer"' >< res && 
     '="admin"' >< res && '="rviewer"' >< res)
  {
      report = report_vuln_url(port:bric_port, url:url);
      security_message(port:bric_port, data:report);
      exit(0);
  }
}
