###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_timelib_meridian_heap_bof_vuln_lin.nasl 7734 2017-11-10 11:35:05Z santu $
#
# PHP 'timelib_meridian' Heap Based Buffer Overflow Vulnerability (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812073");
  script_version("$Revision: 7734 $");
  script_cve_id("CVE-2017-16642");
  script_bugtraq_id(101745);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-11-10 12:35:05 +0100 (Fri, 10 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-09 18:55:09 +0530 (Thu, 09 Nov 2017)");
  script_name("PHP 'timelib_meridian' Heap Based Buffer Overflow Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to heap buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of the detect NVT and check if the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the date
  extension's 'timelib_meridian' handling of 'front of' and 'back of' directives.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  attacker to execute arbitrary code with elevated privileges within the context
  of a privileged process.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"PHP versions before 5.6.32, 7.x before 7.0.25,
  and 7.1.x before 7.1.11");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.6.32, 7.0.25, 7.1.11,
  or later. For updates refer to http://www.php.net");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://php.net/ChangeLog-7.php");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=75055");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

fix = "";
phpVers = "";
phpPort = "";

if(!phpPort = get_app_port(cpe:CPE)){
  exit(0);
}

infos = get_app_version_and_location( cpe:CPE, port:phpPort, exit_no_version:TRUE);
phpVers = infos['version'];
path = infos['location'];


if(version_is_less(version:phpVers, test_version:"5.6.32")){
  fix = "5.6.32";
}

else if(version_in_range(version:phpVers, test_version:"7.0", test_version2:"7.0.24")){
  fix = "7.0.25";
}

else if(phpVers =~ "^7\.1" && version_is_less(version:phpVers, test_version:"7.1.11")){
  fix = "7.1.11";
}

if(fix)
{
  report = report_fixed_ver(installed_version:phpVers, fixed_version:fix, install_path:path);
  security_message(port:phpPort, data:report);
  exit(0);
}
exit(0);
