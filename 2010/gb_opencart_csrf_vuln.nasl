###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opencart_csrf_vuln.nasl 8287 2018-01-04 07:28:11Z teissa $
#
# OpenCart Cross-Site Request Forgery Vulnerability
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

tag_impact = "Successful exploitation will allow attackers to perform CSRF attacks,
  which will aid in further attacks.
  Impact Level: Application";
tag_affected = "OpenCart Version 1.4.7 and prior.";
tag_insight = "The flaw is caused by improper validation of user-supplied input in index.php,
  that allows remote attackers to hijack the authentication of an application
  administrator for requests that create an administrative account via a POST
  request with the route parameter set to 'user/user/insert'.";
tag_solution = "Upgrade to OpenCart version 1.4.8 or later,
  For updates refer to http://www.opencart.com";
tag_summary = "The host is running OpenCart and is prone to cross-site request
  forgery vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801227");
  script_version("$Revision: 8287 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-04 08:28:11 +0100 (Thu, 04 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-06-16 08:26:33 +0200 (Wed, 16 Jun 2010)");
  script_cve_id("CVE-2010-1610");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("OpenCart Cross-Site Request Forgery Vulnerability");


  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("opencart_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/509313/100/0/threaded");
  script_xref(name : "URL" , value : "http://forum.opencart.com/viewtopic.php?f=16&t=10203&p=49654&hilit=csrf#p49654");
  script_xref(name : "URL" , value : "http://blog.visionsource.org/2010/01/28/opencart-csrf-vulnerability/");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Get version from KB
ver = get_kb_item("www/" + port + "/opencart");
cartVer = eregmatch(pattern:"^(.+) under (/.*)$", string:ver);

if(cartVer[1])
{
   ## Check for OpenCart Version prior to 1.4.8
   if(version_is_less(version:cartVer[1], test_version:"1.4.8")) {
     security_message(port);
   }
}
