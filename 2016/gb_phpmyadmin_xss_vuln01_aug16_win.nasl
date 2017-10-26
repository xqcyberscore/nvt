###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_xss_vuln01_aug16_win.nasl 7545 2017-10-24 11:45:30Z cfischer $
#
# phpMyAdmin Double URL Decoding Cross Site Scripting Vulnerability (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.808253");
  script_version("$Revision: 7545 $");
  script_cve_id("CVE-2016-5099");
  script_bugtraq_id(90877);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 13:45:30 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"creation_date", value:"2016-08-04 13:01:28 +0530 (Thu, 04 Aug 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("phpMyAdmin Double URL Decoding Cross Site Scripting Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with phpMyAdmin
  and is prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient validation 
  of user supplied inputs that are mishandled during double URL decoding.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML via special characters.

  Impact Level: Application");

  script_tag(name:"affected", value:"phpMyAdmin versions 4.4.x before 4.4.15.6 
  and 4.6.x before 4.6.2 on Windows.");

  script_tag(name: "solution" , value:"Upgrade to phpMyAdmin version 4.4.15.6 or
  4.6.2 or later.
  For updates refer to https://www.phpmyadmin.net");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://www.phpmyadmin.net/security/PMASA-2016-16");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

##Check for version 4.4.x before 4.4.15.6
if(phpVer =~ "^(4\.4)")
{
  if(version_is_less(version:phpVer, test_version:"4.4.15.6"))
  {
    fix = "4.4.15.6";
    VULN = TRUE;
  }
}

##Check for version 4.6.x before 4.6.2
else if(phpVer =~ "^(4\.6)")
{
  if(version_is_less(version:phpVer, test_version:"4.6.2"))
  {
    fix = "4.6.2";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:phpVer, fixed_version:fix);
  security_message(port:phpPort, data:report);
  exit(0);
}
