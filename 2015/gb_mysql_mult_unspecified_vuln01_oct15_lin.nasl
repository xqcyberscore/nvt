
##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_mult_unspecified_vuln01_oct15_lin.nasl 7572 2017-10-26 08:08:35Z cfischer $
# Oracle MySQL Multiple Unspecified Vulnerabilities-01 Oct15 (Linux)
#
# Authors:
# Tameem Eissa <tameem.eissa..at..greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

tag_impact = "Successful exploitation will allows an authenticated remote attacker to affect confidentiality, integrity, and
  availability via unknown vectors.

  Impact Level: Application.";

tag_summary = "This host is running MySQL 5.5.45 or earlier,  MySQL 5.6.26 or earlier  and is prone to Denial of Service attack.. ";

tag_affected = "Oracle MySQL Server 5.5.45 and earlier
  and 5.6.26 and earlier on Linux" ;

tag_solution = "Apply the patch from the link, : http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html#AppendixMSQL";

CPE = "cpe:/a:oracle:mysql";


if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107018");
  script_version("$Revision: 7572 $");
  script_cve_id("CVE-2015-4913", "CVE-2015-4830", "CVE-2015-4826", "CVE-2015-4815",
                "CVE-2015-4807", "CVE-2015-4802", "CVE-2015-4792", "CVE-2015-4870",
                "CVE-2015-4861", "CVE-2015-4858", "CVE-2015-4836");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 10:08:35 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2016-07-01 12:46:24 +0530 (Fri, 01 Jul 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Oracle MySQL Multiple Unspecified Vulnerabilities-01 Oct15 (Linux)");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed","Host/runs_unixoide");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
mysqlVer = "";
sqlPort = "";

## Get Port
if(!sqlPort = get_app_port(cpe:CPE)){
  exit(0);
}


## Get version
if(!mysqlVer = get_app_version(cpe:CPE, port:sqlPort))
{
  CPE = "cpe:/a:mysql:mysql";
  if(!mysqlVer = get_app_version(cpe:CPE, port:sqlPort)){
    exit(0);
  }
}

if(mysqlVer =~ "^(5\.(5|6))")
{
  if(version_in_range(version:mysqlVer, test_version:"5.5", test_version2:"5.5.45")||
     version_in_range(version:mysqlVer, test_version:"5.6", test_version2:"5.6.26"))
  {
    security_message(sqlPort);
    exit(0);
  }
}
