###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_mult_vuln_oct_09.nasl 6995 2017-08-23 11:52:03Z teissa $
#
# TYPO3 Multiple Vulnerabilities Oct09
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.803990";
CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6995 $");
  script_cve_id("CVE-2009-3628", "CVE-2009-3629", "CVE-2009-3630", "CVE-2009-3631",
                "CVE-2009-3632", "CVE-2009-3633", "CVE-2009-3635", "CVE-2009-3636");
  script_bugtraq_id(36801);
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2017-08-23 13:52:03 +0200 (Wed, 23 Aug 2017) $");
  script_tag(name:"creation_date", value:"2013-12-27 12:45:17 +0530 (Fri, 27 Dec 2013)");
  script_name("TYPO3 Multiple Vulnerabilities Oct09");

tag_summary =
"This host is installed with TYPO3 and is prone to multiple vulnerabilities.";

tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

tag_insight =
'Multiple error exists in the application,
- Multiple errors in Backend subcomponent, which fails to validate user
supplied input properly.
- An error exist in Frontend Editing, which fails to sanitize URL parameters
properly.
- An error exist in API function t3lib_div::quoteJSvalue, which fails to
validate user supplied input properly.
- Multiple error exist in Install Tool, which allows login with know md5 hash of
Install Tool password.';

tag_impact =
"Successful exploitation will allow remote attackers to steal the
victim's cookie-based authentication credentials or execute arbitrary code.

Impact Level: System/Application";

tag_affected =
"TYPO3 versions 4.0.13 and below, 4.1.0 to 4.1.12, 4.2.0 to 4.2.9 and 4.3.0beta1";

tag_solution =
"Upgrade to TYPO3 version 4.1.13, 4.2.10, 4.3beta2 or later,
For updates refer to, http://typo3.org/";


  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53917");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37122");
  script_xref(name : "URL" , value : "http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-sa-2009-016/");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
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
if(!typoPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

if(typoVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:typoPort))
{
  if( typoVer !~ "[0-9]+\.[0-9]+\.[0-9]+" ) exit( 0 ); # Version is not exact enough
  ## Check for version
  if(version_is_less(version:typoVer, test_version:"4.1.13") ||
     version_in_range(version:typoVer, test_version:"4.2.0", test_version2:"4.2.9"))
  {
    security_message(typoPort);
    exit(0);
  }
}
