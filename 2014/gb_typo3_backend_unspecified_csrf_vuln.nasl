###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_backend_unspecified_csrf_vuln.nasl 2014-01-10 12:10:05Z jan$
#
# TYPO3 Backend Unspecified CSRF Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.804222";
CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6692 $");
  script_bugtraq_id(46377);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:57:43 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-01-10 12:10:05 +0530 (Fri, 10 Jan 2014)");
  script_name("TYPO3 Backend Unspecified CSRF Vulnerability");

tag_summary =
"This host is installed with TYPO3 and is prone to cross site request forgery
vulnerability.";

tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

tag_insight =
'An error exist in typo3 backend, which is caused by improper validation of
user supplied input.';

tag_impact =
"Successful exploitation will allow remote attackers to perform cross-site
scripting attacks, Web cache poisoning, and other malicious activities.

Impact Level: Application";

tag_affected =
"TYPO3 version 4.2.x to 4.2.16, 4.3.x to 4.3.9, and 4.4.x to 4.4.5";

tag_solution =
"Upgrade to TYPO3 version 4.5 or later,
for updates
http://typo3.org/";


  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/65387");
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
if(!typoPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

if(typoVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:typoPort))
{
  if( typoVer !~ "[0-9]+\.[0-9]+\.[0-9]+" ) exit( 0 ); # Version is not exact enough
  ## Check for version
  if(version_in_range(version:typoVer, test_version:"4.2.0", test_version2:"4.2.16") ||
     version_in_range(version:typoVer, test_version:"4.3.0", test_version2:"4.3.9") ||
     version_in_range(version:typoVer, test_version:"4.4.0", test_version2:"4.4.5"))
  {
    security_message(typoPort);
    exit(0);
  }
}
