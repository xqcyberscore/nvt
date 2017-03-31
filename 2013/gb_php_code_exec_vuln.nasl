###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_code_exec_vuln.nasl 4500 2016-11-14 14:30:24Z cfi $
#
# PHP Remote Code Execution Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804160");
  script_version("$Revision: 4500 $");
  script_cve_id("CVE-2013-6712");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-11-14 15:30:24 +0100 (Mon, 14 Nov 2016) $");
  script_tag(name:"creation_date", value:"2013-12-06 13:02:20 +0530 (Fri, 06 Dec 2013)");
  script_name("PHP Remote Code Execution Vulnerability");

  tag_summary = "This host is installed with PHP and is prone to remote code execution
  vulnerability.";

  tag_vuldetect = "Get the installed version of PHP with the help of detect NVT and check
  the version is vulnerable or not.";

  tag_insight = "The flaw is due to error in 'scan function' in
  'ext/date/lib/parse_iso_intervals.c' which does not validate user-supplied
  input when handling 'DateInterval' objects.";

  tag_impact = "Successful exploitation will allow remote attackers to allow a remote attacker
  to cause a heap-based buffer overflow, resulting in a denial of service.

  Impact Level: Application";

  tag_affected = "PHP versions 5.5.6 and prior.";

  tag_solution = "Upgrade to PHP version 5.5.8 or later.
  For updates refer to http://www.php.net";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);

  script_xref(name:"URL", value:"http://git.php.net/?p=php-src.git;a=commit;h=12fe4e90be7bfa2a763197079f68f5568a14e071");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
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
if(version_in_range(version:phpVer, test_version:"5.5.0", test_version2:"5.5.6")){
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.5.8");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);
