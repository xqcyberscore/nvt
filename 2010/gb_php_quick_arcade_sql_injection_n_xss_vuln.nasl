##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_quick_arcade_sql_injection_n_xss_vuln.nasl 8338 2018-01-09 08:00:38Z teissa $
#
# PHP Quick Arcade SQL Injection and Cross Site Scripting Vulnerabilities
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
################################i###############################################

tag_impact = "Successful exploitation will allow attacker to steal cookie-based
authentication credentials, compromise the application, access or modify data.

Impact Level: Application.";

tag_affected = "PHP-Quick-Arcade version 3.0.21 and prior.";

tag_insight = "The flaws are due to,
- Input validation errors in the 'Arcade.php' and 'acpmoderate.php' scripts
when processing the 'phpqa_user_c' cookie or the 'id' parameter, which could
be exploited by malicious people to conduct SQL injection attacks.
- Input validation error in the 'acpmoderate.php' script when processing the
'serv' parameter, which could allow cross site scripting attacks.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running PHP Quick Arcade and is prone to SQL
injection and cross site scripting Vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801364");
  script_version("$Revision: 8338 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-09 09:00:38 +0100 (Tue, 09 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-06-21 15:32:44 +0200 (Mon, 21 Jun 2010)");
  script_cve_id("CVE-2010-1661", "CVE-2010-1662");
  script_bugtraq_id(39733);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PHP Quick Arcade SQL Injection and Cross Site Scripting Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/12416/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1013");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1004-exploits/phpquickarcade-sqlxss.txt");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_quick_arcade_detect.nasl");
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

## Get HTTP Port
phpqaPort = get_http_port(default:80);
if(!phpqaPort){
  exit(0);
}

## Get the version from KB
phpqaVer = get_kb_item("www/" + phpqaPort + "/PHP-Quick-Arcade");
if(!phpqaVer){
  exit(0);
}

phpqaVer = eregmatch(pattern:"^(.+) under (/.*)$", string:phpqaVer);
if(isnull(phpqaVer[1])){
  exit(0);
}

## Check the version of PHP Quick Arcade
if(version_is_less_equal(version:phpqaVer[1], test_version:"3.0.21")){
  security_message(phpqaPort);
}
