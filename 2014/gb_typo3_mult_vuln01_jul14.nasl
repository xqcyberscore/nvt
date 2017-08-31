###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_mult_vuln01_jul14.nasl 6750 2017-07-18 09:56:47Z teissa $
#
# TYPO3 Multiple Vulnerabilities-01 July-2104
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804464");
  script_version("$Revision: 6750 $");
  script_cve_id("CVE-2014-3941", "CVE-2014-3943");
  script_bugtraq_id(67626, 67625);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2017-07-18 11:56:47 +0200 (Tue, 18 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-07-03 13:45:50 +0530 (Thu, 03 Jul 2014)");
  script_name("TYPO3 Multiple Vulnerabilities-01 July-2104");

tag_summary =
"This host is installed with TYPO3 and is prone to multiple vulnerabilities.";

tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

tag_insight =
"The flaws are due to,
- Failing to properly validate the HTTP host-header TYPO3 CMS is susceptible
  to host spoofing.
- Failing to properly encode user input, several backend components are
  susceptible to Cross-Site Scripting, allowing authenticated editors to
  inject arbitrary HTML or JavaScript by crafting URL parameters.";

tag_impact =
"Successful exploitation will allow remote attackers to conduct host spoofing
and cross-site scripting attacks.

Impact Level: Application";

tag_affected =
"TYPO3 versions 4.5.0 to 4.5.33, 4.7.0 to 4.7.18, 6.0.0 to 6.0.13,
6.1.0 to 6.1.8 and 6.2.0 to 6.2.2";

tag_solution =
"Upgrade to TYPO3 version 4.5.34, 4.7.19, 6.0.14, 6.1.9 or 6.2.3 or later,
For updates refer to http://typo3.org";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/58901");
  script_xref(name : "URL" , value : "http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2014-001");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");
include("global_settings.inc");

## Variable initialisation
typoPort = "";
typoVer = "";

## Get Application HTTP Port
if(!typoPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(typoVer = get_app_version(cpe:CPE, port:typoPort))
{
  if( typoVer !~ "[0-9]+\.[0-9]+\.[0-9]+" ) exit( 0 ); # Version is not exact enough
  ## Check for version
  if(version_in_range(version:typoVer, test_version:"4.5.0", test_version2:"4.5.33") ||
     version_in_range(version:typoVer, test_version:"4.7.0", test_version2:"4.7.18") ||
     version_in_range(version:typoVer, test_version:"6.0.0", test_version2:"6.0.13") ||
     version_in_range(version:typoVer, test_version:"6.1.0", test_version2:"6.1.8") ||
     version_in_range(version:typoVer, test_version:"6.2.0", test_version2:"6.2.2"))
  {
    security_message(typoPort);
    exit(0);
  }
}
