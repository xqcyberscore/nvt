###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_ssl_cert_val_sec_bypass_vuln_win.nasl 7548 2017-10-24 12:06:02Z cfischer $
#
# PHP SSL Certificate Validation Security Bypass Vulnerability (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.803739");
  script_version("$Revision: 7548 $");
  script_cve_id("CVE-2013-4248");
  script_bugtraq_id(61776);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 14:06:02 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"creation_date", value:"2013-08-19 17:10:43 +0530 (Mon, 19 Aug 2013)");
  script_name("PHP SSL Certificate Validation Security Bypass Vulnerability (Windows)");

  tag_summary = "This host is running PHP and is prone to security bypass vulnerability.";

  tag_insight = "The flaw is due to the SSL module not properly handling NULL bytes inside
  'subjectAltNames' general names in the server SSL certificate.";

  tag_vuldetect = "Get the installed version of PHP with the help of detect NVT and check it
  is vulnerable or not.";

  tag_impact = "Successful exploitation will allow remote attackers to spoof the server via
  a MitM (Man-in-the-Middle) attack and disclose potentially sensitive
  information.

  Impact Level: Application";

  tag_affected = "PHP versions before 5.4.18 and 5.5.x before 5.5.2 on Windows.";

  tag_solution = "Upgrade to PHP version 5.4.18 or 5.5.2 or later,
  For updates refer to http://php.net";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);

  script_xref(name:"URL", value:"http://secunia.com/advisories/54480");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://git.php.net/?p=php-src.git;a=commit;h=2874696a5a8d46639d261571f915c493cd875897");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl","gb_php_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("php/installed","Host/runs_windows");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

##Check for PHP version
if(version_is_less(version:phpVer, test_version:"5.4.18") ||
   version_in_range(version:phpVer, test_version:"5.5", test_version2:"5.5.1")){
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.4.18/5.5.2");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);
