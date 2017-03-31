###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_mult_dos_vuln_jun14.nasl 4499 2016-11-14 14:06:43Z cfi $
#
# PHP CDF File Parsing Denial of Service Vulnerabilities - 01 - Jun14
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804639");
  script_version("$Revision: 4499 $");
  script_cve_id("CVE-2014-0237", "CVE-2014-0238");
  script_bugtraq_id(67759, 67765);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-11-14 15:06:43 +0100 (Mon, 14 Nov 2016) $");
  script_tag(name:"creation_date", value:"2014-06-16 10:22:50 +0530 (Mon, 16 Jun 2014)");
  script_name("PHP CDF File Parsing Denial of Service Vulnerabilities - 01 - Jun14");

  tag_summary = "This host is installed with PHP and is prone to denial of service
  vulnerabilities.";

  tag_vuldetect = "Get the installed version of PHP with the help of detect NVT and check
  the version is vulnerable or not.";

  tag_insight = "The flaw is due to
  - An error due to an infinite loop within the 'unpack_summary_info' function in
  src/cdf.c script.
  - An error within the 'cdf_read_property_info' function in src/cdf.c script.";

  tag_impact = "Successful exploitation will allow remote attackers to conduct denial of
  service attacks.

  Impact Level: Application";

  tag_affected = "PHP version 5.x before 5.4.29 and 5.5.x before 5.5.13";

  tag_solution = "Upgrade to PHP version 5.4.29 or 5.5.13 or later. For updates refer to
  http://php.net";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://secunia.com/advisories/58804");
  script_xref(name:"URL", value:"https://www.hkcert.org/my_url/en/alert/14060401");

  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("php/installed");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

## check the version
if(version_in_range(version:phpVer, test_version:"5.5.0", test_version2:"5.5.12")||
   version_in_range(version:phpVer, test_version:"5.0.0", test_version2:"5.4.28")){
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.4.29/5.5.13");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);