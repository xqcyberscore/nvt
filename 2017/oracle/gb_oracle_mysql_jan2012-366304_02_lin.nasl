###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_mysql_jan2012-366304_02_lin.nasl 8367 2018-01-11 07:32:43Z cfischer $
#
# Oracle Mysql Security Updates (jan2012-366304) 02 - Linux
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

CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812345");
  script_version("$Revision: 8367 $");
  script_cve_id("CVE-2012-0486", "CVE-2012-0487", "CVE-2012-0488", "CVE-2012-0489",
                "CVE-2012-0117", "CVE-2012-0495", "CVE-2012-0494", "CVE-2012-0496",
                "CVE-2012-0491", "CVE-2012-0493");
  script_bugtraq_id(51514, 51503, 51506, 51510, 51521, 51522, 51523, 51507, 51518, 51525);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-01-11 08:32:43 +0100 (Thu, 11 Jan 2018) $");
  script_tag(name:"creation_date", value:"2017-12-14 15:15:42 +0530 (Thu, 14 Dec 2017)");
  script_name("Oracle Mysql Security Updates (jan2012-366304) 02 - Linux");

  script_tag(name:"summary", value:"This host is running Oracle MySQL and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws exists due to multiple
  unspecified errors in MySQL Server.");

  script_tag(name: "impact" , value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to affect integrity, availability
  and confidentiality. 

  Impact Level: Application");

  script_tag(name: "affected" , value:"Oracle MySQL version 5.5.x on Linux");

  script_tag(name:"solution", value:"Apply the patch from below link,
  http://www.oracle.com/technetwork/topics/security/cpujan2012-366304.html");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpujan2012-366304.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MySQL/installed", "Host/runs_unixoide");
  script_require_ports("Services/mysql", 3306);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

mysqlVer = "";
sqlPort = "";
mysqlPath = "";

if(!sqlPort = get_app_port(cpe:CPE))
{
  CPE = "cpe:/a:mysql:mysql";
  if(!sqlPort = get_app_port(cpe:CPE)){
    exit(0);
  }
}

if(!infos = get_app_version_and_location(cpe:CPE, port:sqlPort, exit_no_version:TRUE)) exit(0);
mysqlVer = infos['version'];
mysqlPath = infos['location'];

if(version_in_range(version:mysqlVer, test_version:"5.5", test_version2:"5.5.19"))
{
  report = report_fixed_ver(installed_version:mysqlVer, fixed_version: "Apply the patch", install_path:mysqlPath);
  security_message(port:sqlPort, data: report);
  exit(0);
}
exit(0);
