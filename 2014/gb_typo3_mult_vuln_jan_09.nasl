###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_mult_vuln_jan_09.nasl 6750 2017-07-18 09:56:47Z teissa $
#
# TYPO3 Multiple Vulnerabilities Jan09
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

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803988");
  script_version("$Revision: 6750 $");
  script_cve_id("CVE-2009-0255", "CVE-2009-0256", "CVE-2009-0257", "CVE-2009-0258");
  script_bugtraq_id(33376);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-18 11:56:47 +0200 (Tue, 18 Jul 2017) $");
  script_tag(name:"creation_date", value:"2013-12-26 16:32:44 +0530 (Thu, 26 Dec 2013)");
  script_name("TYPO3 Multiple Vulnerabilities Jan09");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/48135");
  script_xref(name:"URL", value:"http://typo3.org/teams/security/security-bulletins/typo3-core/TYPO3-SA-2009-001/");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code or steal the victim's cookie-based authentication credentials.

  Impact Level: Application");
  script_tag(name:"vuldetect", value:"Get the installed version with the help of detect NVT and check the version
  is vulnerable or not.");
  script_tag(name:"insight", value:'Multiple error exists in the application,
  - An error exist in Indexed Search Engine system extension which fails to
  validate user-supplied input properly.
  - An error exist in session tokens, which is caused by the improper validation.
  - An error exist in Workspace module which fails to validate user-supplied
  input properly.');
  script_tag(name:"solution", value:"Upgrade to TYPO3 version 4.0.10, 4.1.8, 4.2.4 or later,
  For updates refer to, http://typo3.org/");
  script_tag(name:"summary", value:"This host is installed with TYPO3 and is prone to multiple vulnerabilities.");
  script_tag(name:"affected", value:"TYPO3 versions 4.0.0 to 4.0.9, 4.1.0 to 4.1.7, 4.2.0 to 4.2.3");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version(cpe:CPE, port:port ) ) exit( 0 );

if( vers !~ "[0-9]+\.[0-9]+\.[0-9]+" ) exit( 0 ); # Version is not exact enough

## Check for version
if( version_in_range( version:vers, test_version:"4.0.0", test_version2:"4.0.9" ) ||
    version_in_range( version:vers, test_version:"4.1.0", test_version2:"4.1.7" ) ||
    version_in_range( version:vers, test_version:"4.2.0", test_version2:"4.2.3" ) ) {

    report = report_fixed_ver( installed_version:vers, fixed_version:"4.0.10, 4.1.8, 4.2.4 or later" );
    security_message( port:port, data:report );
    exit( 0 );
}

exit( 99 );
