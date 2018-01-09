###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zeuscart_xss_vuln.nasl 8296 2018-01-05 07:28:01Z teissa $
#
# ZeusCart 'search' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to execute arbitrary
HTML and script code in a user's browser session in the context of a vulnerable
site. This may allow the attacker to steal cookie-based authentication credentials
and to launch other attacks.

Impact Level: Application";

tag_affected = "ZeusCart Versions 3.0 and 2.3";

tag_insight = "The flaw is caused by improper validation of user-supplied input
via the 'search' parameter in a 'search' action which allows attacker to execute
arbitrary HTML and script code in a user's browser session.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is running ZeusCart and is prone to cross site scripting
vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801249");
  script_version("$Revision: 8296 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-05 08:28:01 +0100 (Fri, 05 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-08-10 14:39:31 +0200 (Tue, 10 Aug 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("ZeusCart 'search' Parameter Cross Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://secpod.org/blog/?p=109");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35319/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/512885");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SECPOD_ZeusCart_XSS.txt");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zeuscart_detect.nasl");
  script_require_ports("Services/www", 80);
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

## Get HTTP Port
zcPort = get_http_port(default:80);
if(!zcPort){
  exit(0);
}

## Get version and directory from KB
zcVer = get_version_from_kb(port:zcPort, app:"ZeusCart");
zcDir = get_dir_from_kb(port:zcPort, app:"ZeusCart");
if(!zcVer || !zcDir) {
  exit(0);
}

if(!safe_checks())
{
  ## Construct attack request
  zcReq = http_post(port:zcPort, item:string(zcDir,"/"),
                  data:"%22%20style=x:expression(alert(document.cookie))><");
  zcRes = http_keepalive_send_recv(port:zcPort, data:zcReq, bodyonly:TRUE);

  ## Confirm exploit worked by checking the response
  if((zcRes =~ "HTTP/1\.. 200" && 'style=x:expression(alert(document.cookie))' >< zcRes))
  {
    security_message(zcPort);
    exit(0);
  }
}

if(version_is_equal(version:zcVer, test_version:"3.0") ||
   version_is_equal(version:zcVer, test_version:"2.3")){
    security_message(zcPort);
}
