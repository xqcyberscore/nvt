###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_backronym_vuln_june16_win.nasl 5083 2017-01-24 11:21:46Z cfi $
#
# Oracle MySQL Backronym Vulnerability June16 (Windows)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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

CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808063");
  script_version("$Revision: 5083 $");
  script_cve_id("CVE-2015-3152");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-01-24 12:21:46 +0100 (Tue, 24 Jan 2017) $");
  script_tag(name:"creation_date", value:"2016-06-02 16:42:56 +0530 (Thu, 02 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Oracle MySQL Backronym Vulnerability June16 (Windows)");

  script_tag(name:"summary", value:"This host is running Oracle MySQL and is
  prone to the backronym vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exist due to improper validation
  of MySQL client library when establishing a secure connection to a MySQL
  server using the --ssl option.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  man-in-the-middle attackers to spoof servers via a cleartext-downgrade
  attack.

  Impact Level: Application");

  script_tag(name:"affected", value:"Oracle MySQL Server 5.7.2 and earlier
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to version Oracle MySQL Server 5.7.3 or
  later. For updates refer to http://www.oracle.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.ocert.org/advisories/ocert-2015-003.html");
  script_xref(name : "URL" , value : "https://duo.com/blog/backronym-mysql-vulnerability");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_summary("Check for the vulnerable version of Oracle MySQL");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed","Host/runs_windows");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable Initialization
mysqlVer = "";
sqlPort = "";

if(host_runs("Windows") != "yes"){
  exit(0);
}

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

if(version_is_less(version:mysqlVer, test_version:"5.7.3"))
{
  report = report_fixed_ver(installed_version:mysqlVer, fixed_version:"5.7.3");
  security_message(data:report, port:sqlPort);
  exit(0);
}
