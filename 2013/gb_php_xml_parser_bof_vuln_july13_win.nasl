###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_xml_parser_bof_vuln_july13_win.nasl 5086 2017-01-24 11:34:51Z cfi $
#
# PHP XML Handling Heap Buffer Overflow Vulnerability - Jul13 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803729");
  script_version("$Revision: 5086 $");
  script_cve_id("CVE-2013-4113");
  script_bugtraq_id(61128);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-01-24 12:34:51 +0100 (Tue, 24 Jan 2017) $");
  script_tag(name:"creation_date", value:"2013-07-30 12:28:05 +0530 (Tue, 30 Jul 2013)");
  script_name("PHP XML Handling Heap Buffer Overflow Vulnerability - Jul13 (Windows)");

   tag_summary = "This host is running PHP and is prone to heap based buffer overflow
  vulnerability.";

  tag_insight = "The flaw is triggered as user-supplied input is not properly validated when
  handling malformed XML input.";

  tag_vuldetect = "Get the installed version of PHP with the help of detect NVT and
  check it is vulnerable or not.";

  tag_impact = "Successful exploitation will allow attackers to cause a heap-based buffer
  overflow, resulting in a denial of service or potentially allowing the
  execution of arbitrary code.

  Impact Level: Application";

  tag_affected = "PHP version prior to 5.3.27";

  tag_solution = "Upgrade to PHP version 5.3.27 or later,
  For updates refer to http://php.net/";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);

  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=65236");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q3/88");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Jul/106");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("os_detection.nasl","gb_php_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("php/installed","Host/runs_windows");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

## If its not windows exit
if(host_runs("windows") != "yes"){
  exit(0);
}

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(phpVer =~ "^(5\.3)"){
  ##Check for PHP version
  if(version_in_range(version:phpVer, test_version:"5.3", test_version2: "5.3.26")){
    report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.3.27");
    security_message(data:report, port:phpPort);
    exit(0);
  }
}

exit(99);
