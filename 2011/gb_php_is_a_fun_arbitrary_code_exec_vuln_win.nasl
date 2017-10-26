###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_is_a_fun_arbitrary_code_exec_vuln_win.nasl 7550 2017-10-24 12:17:52Z cfischer $
#
# PHP 'is_a()' Function Remote Arbitrary Code Execution Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802504");
  script_version("$Revision: 7550 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 14:17:52 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"creation_date", value:"2011-11-08 13:11:11 +0530 (Tue, 08 Nov 2011)");
  script_cve_id("CVE-2011-3379");
  script_bugtraq_id(49754);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PHP 'is_a()' Function Remote Arbitrary Code Execution Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl","gb_php_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("php/installed","Host/runs_windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/46107/");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=741020");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/519770/30/0/threaded");
  script_xref(name:"URL", value:"http://www.byte.nl/blog/2011/09/23/security-bug-in-is_a-function-in-php-5-3-7-5-3-8/");

  tag_solution = "Update to version 5.3.9 or later,
  For updates refer to http://php.net/downloads.php";

  tag_impact = "Successful exploitation could allow remote attackers to execute
  arbitrary PHP code by including arbitrary files from remote resources.

  Impact Level: Application/System";

  tag_affected = "PHP Version 5.3.7 and 5.3.8 on Windows.";

  tag_insight = "The flaw is due to error in 'is_a()' function. It receives
  strings as first argument, which can lead to the '__autoload()' function being
  called unexpectedly and do not properly verify input in their '__autoload()'
  function, which leads to an unexpected attack vectors.";

  tag_summary = "This host is installed with PHP and is prone to remote arbitrary
  code execution vulnerability.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

##Check for PHP version
if(version_is_equal(version:phpVer, test_version:"5.3.7") ||
  version_is_equal(version:phpVer, test_version:"5.3.8")){
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.3.9");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);
