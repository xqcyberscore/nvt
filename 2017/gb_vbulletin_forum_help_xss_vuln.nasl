###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vbulletin_forum_help_xss_vuln.nasl 8152 2017-12-18 06:27:14Z cfischer $
#
# vBulletin Forum 'forum/help' Page Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:vbulletin:vbulletin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811314");
  script_version("$Revision: 8152 $");
  script_cve_id("CVE-2014-9469");
  script_bugtraq_id(72592);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-18 07:27:14 +0100 (Mon, 18 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-08-31 12:28:37 +0530 (Thu, 31 Aug 2017)");
  script_name("vBulletin Forum 'forum/help' Page Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with vBulletin and is prone
  to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to the programming code
  flaw occurs at 'forum/help' page. Add 'hash symbol' first. Then add script at
  the end of it.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to execute arbitrary script code in the browser of an
  unsuspecting user in the context of the affected site. This may allow the
  attacker to steal cookie-based authentication credentials and launch other
  attacks.

  Impact Level: Application");

  script_tag(name:"affected", value:"VBulletin versions 5.1.3, 5.0.5, 4.2.2, 3.8.7,
  3.6.7, 3.6.0 and 3.5.4.");

  script_tag(name:"solution", value:"No solution or patch is available as of
  18th December, 2017. Information regarding this issue will be updated once solution details
  are available. For updates refer to http://www.vbulletin.com");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name : "URL" , value : "https://vuldb.com/?id.69174");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2015/Feb/49");
  script_xref(name : "URL" , value : "http://www.tetraph.com/blog/xss-vulnerability/cve-2014-9469-vbulletin-xss");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("vbulletin_detect.nasl");
  script_mandatory_keys("vBulletin/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
vPort = "";
vVer = "";

## get the port
if(!vPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get the version
if(!vVer = get_app_version(cpe:CPE, port:vPort)){
  exit(0);
}

foreach affected_version (make_list("5.1.3", "5.0.5", "4.2.2", "3.8.7", "3.6.7", "3.6.0", "3.5.4"))
{
  if(affected_version == vVer) 
  {
    report = report_fixed_ver(installed_version:vVer, fixed_version:"NoneAvailable");
    security_message(data:report, port:vPort);
    exit(0);
  }
}
exit(0);
