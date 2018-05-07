###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_mysql_apr2018-3678067_03_win.nasl 9733 2018-05-04 14:11:22Z cfischer $
#
# Oracle Mysql Security Updates (apr2018-3678067) 03 - Windows
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.813146");
  script_version("$Revision: 9733 $");
  script_cve_id("CVE-2018-2846", "CVE-2018-2776", "CVE-2018-2762", "CVE-2018-2816",
                "CVE-2018-2769", "CVE-2018-2780", "CVE-2018-2786", "CVE-2018-2839",
                "CVE-2018-2778", "CVE-2018-2779", "CVE-2018-2775", "CVE-2018-2777",
                "CVE-2018-2810", "CVE-2018-2812", "CVE-2018-2759" );
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-05-04 16:11:22 +0200 (Fri, 04 May 2018) $");
  script_tag(name:"creation_date", value:"2018-04-19 10:34:42 +0530 (Thu, 19 Apr 2018)");
  script_name("Oracle Mysql Security Updates (apr2018-3678067) 03 - Windows");

  script_tag(name:"summary", value:"This host is running Oracle MySQL and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws exists due to

  - An error in the 'Server:Performance Schema' component of MySQL Server.

  - An error in the 'Group Replication GCS' component of MySQL Server.

  - An error in the 'Server:Connection' component of MySQL Server.

  - Multiple errors in the 'Server:Optimizer' component of MySQL Server.

  - An error in the 'Server:Pluggable Auth' component of MySQL Server.

  - An error in the 'Server:DML' component of MySQL Server.

  - Multiple errors in the 'InnoDB' component of MySQL Server.");

  script_tag(name: "impact" , value:"Successful exploitation of this
  vulnerability will allow remote to conduct a denial of service and have an
  impact on integrity.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Oracle MySQL version 5.7.21 and earlier
  on Windows");

  script_tag(name:"solution", value:"Apply the latest patch from vendor. For
  updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed", "Host/runs_windows");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sqlPort = get_app_port(cpe:CPE)){
  exit(0);
}

infos = get_app_version_and_location(cpe:CPE, port:sqlPort, exit_no_version:TRUE);
mysqlVer = infos['version'];
path = infos['location'];

if(version_in_range(version:mysqlVer, test_version:"5.7", test_version2:"5.7.21")){
  report = report_fixed_ver(installed_version:mysqlVer, fixed_version: "Apply the patch", install_path:path);
  security_message(port:sqlPort, data:report);
  exit(99);
}

exit(0);
