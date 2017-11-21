###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_recaptcha_bypass_vuln_nov15_win.nasl 7834 2017-11-20 14:48:51Z cfischer $
#
# phpMyAdmin Security Bypass Vulnerability Nov15 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806548");
  script_version("$Revision: 7834 $");
  script_cve_id("CVE-2015-6830");
  script_bugtraq_id(76674);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-11-20 15:48:51 +0100 (Mon, 20 Nov 2017) $");
  script_tag(name:"creation_date", value:"2015-11-24 10:32:31 +0530 (Tue, 24 Nov 2015)");
  script_name("phpMyAdmin Security Bypass Vulnerability Nov15 (Windows)");

  script_tag(name:"summary", value:"This host is installed with phpMyAdmin and
  is prone to reCaptcha bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to an error in
  'libraries/plugins/auth/AuthenticationCookie.class.php' script while
  implementing multiple-reCaptcha protection mechanism so that it provide a
  correct response to a single reCaptcha.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow
  remote attackers to bypass multiple-reCaptcha protection mechanism.

  Impact Level: Application");

  script_tag(name:"affected", value:"phpMyAdmin versions 4.3.x before 4.3.13.2
  and 4.4.x before 4.4.14.1 on Windows");

  script_tag(name:"solution", value:"Upgrade to phpMyAdmin 4.3.13.2 or 4.4.14.1
  or later. For updates refer http://www.phpmyadmin.net");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2015-4");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed","Host/runs_windows");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

# Variable Initialization
phpPort = "";
phpVer = "";

## get the port
if(!phpPort = get_app_port(cpe:CPE)) exit(0);

## Get the version
if(!phpVer = get_app_version(cpe:CPE, port:phpPort)) exit(0);

##Check for version 4.3.x before 4.3.13.2
if(phpVer =~ "^(4\.3)")
{
  if(version_is_less(version:phpVer, test_version:"4.3.13.2"))
  {
    fix = "4.3.13.2";
    VULN = TRUE;
  }
}

##Check for version 4.4.x before 4.4.14.1
else if(phpVer =~ "^(4\.4)")
{
  if(version_is_less(version:phpVer, test_version:"4.4.14.1"))
  {
    fix = "4.4.14.1";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:phpVer, fixed_version:fix);
  security_message(port:phpPort, data:report);
  exit(0);
}

exit(99);
