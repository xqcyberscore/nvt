###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_mult_vuln01_may16_lin.nasl 7545 2017-10-24 11:45:30Z cfischer $
#
# phpMyAdmin Multiple Vulnerabilities -01 May16 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.807593");
  script_version("$Revision: 7545 $");
  script_cve_id("CVE-2016-2559", "CVE-2016-2562");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 13:45:30 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"creation_date", value:"2016-05-17 12:12:08 +0530 (Tue, 17 May 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("phpMyAdmin Multiple Vulnerabilities -01 May16 (Linux)");

  script_tag(name:"summary", value:"This host is installed with phpMyAdmin
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to, 
  - An input validation error in format function in 
    'libraries/sql-parser/src/Utils/Error.php' script in the SQL parser.    
  - The checkHTTP function in 'libraries/Config.class.php' script 
    does not verify X.509 certificates from api.github.com SSL servers.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML and man-in-the-middle 
  attackers to spoof these servers and obtain sensitive information.

  Impact Level: Application");

  script_tag(name:"affected", value:"phpMyAdmin versions 4.5.x before 4.5.5.1
  on Linux.");

  script_tag(name: "solution" , value:"Upgrade to phpMyAdmin version 4.5.5.1 or 
  later or apply patch from the link mentioned in reference.
  For updates refer to https://www.phpmyadmin.net");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://www.phpmyadmin.net/security/PMASA-2016-10");
  script_xref(name : "URL" , value : "https://www.phpmyadmin.net/security/PMASA-2016-13");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed","Host/runs_unixoide");
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

##Check for version 4.5.x before 4.5.5.1
if(phpVer =~ "^(4\.5)")
{
  if(version_is_less(version:phpVer, test_version:"4.5.5.1"))
  {
    report = report_fixed_ver(installed_version:phpVer, fixed_version:"4.5.5.1");
    security_message(port:phpPort, data:report);
    exit(0);
  }
}
