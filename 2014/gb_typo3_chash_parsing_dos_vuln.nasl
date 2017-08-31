###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_chash_parsing_dos_vuln.nasl 6750 2017-07-18 09:56:47Z teissa $
#
# TYPO3 CHash Parsing Denial of Service Vulnerability
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

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.803995";
CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6750 $");
  script_cve_id("CVE-2011-3584");
  script_bugtraq_id(49622);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2017-07-18 11:56:47 +0200 (Tue, 18 Jul 2017) $");
  script_tag(name:"creation_date", value:"2013-12-31 16:24:40 +0530 (Tue, 31 Dec 2013)");
  script_name("TYPO3 CHash Parsing Denial of Service Vulnerability");

tag_summary =
"This host is installed with TYPO3 and is prone to denial of service
vulnerability.";

tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

tag_insight =
"An error exist in , which application, which fails to disable caching when
an invalid cache hash URL parameter (cHash) is provided.";

tag_impact =
"Successful exploitation will allow attackers to cause a denial of service
condition.

Impact Level: Application";

tag_affected =
"TYPO3 versions 4.2.0 to 4.2.17, 4.3.0 to 4.3.13, 4.4.0 to 4.4.10 and 4.5.0 to
4.5.5";

tag_solution =
"Upgrade to TYPO3 version 4.3.14 or 4.4.11 or 4.5.6 or later,
For updates refer to, http://typo3.org/";


  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/45940/");
  script_xref(name : "URL" , value : "http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2011-003/");
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
  if(version_in_range(version:typoVer, test_version:"4.2.0", test_version2:"4.2.17") ||
     version_in_range(version:typoVer, test_version:"4.3.0", test_version2:"4.3.13") ||
     version_in_range(version:typoVer, test_version:"4.4.0", test_version2:"4.4.10") ||
     version_in_range(version:typoVer, test_version:"4.5.0", test_version2:"4.5.5"))
  {
    security_message(typoPort);
    exit(0);
  }
}
