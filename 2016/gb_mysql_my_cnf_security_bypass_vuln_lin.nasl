###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_my_cnf_security_bypass_vuln_lin.nasl 62907 2016-09-26 13:07:06 +0530 feb$
#
# Oracle Mysql 'my.conf' Security Bypass Vulnerability (Linux)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809331");
  script_version("$Revision: 11640 $");
  script_cve_id("CVE-2016-6662");
  script_bugtraq_id(92912);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-27 09:15:20 +0200 (Thu, 27 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-09-26 12:24:08 +0530 (Mon, 26 Sep 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Oracle Mysql 'my.conf' Security Bypass Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is running Oracle MySQL and is prone
  to security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to datadir is writable by
  the mysqld server, and a user that can connect to MySQL can create 'my.cnf' in
  the datadir using 'SELECT ... OUTFILE'.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local
  users to execute arbitrary code with root privileges by setting malloc_lib.");

  script_tag(name:"affected", value:"Oracle MySQL Server before 5.5.52, 5.6.x
  before 5.6.33, and 5.7.x before 5.7.15 on linux.");

  script_tag(name:"solution", value:"Upgrade to Oracle MySQL Server 5.5.52,
  or 5.6.33, or 5.7.15, or later.
  For updates refer to https://dev.mysql.com/doc/relnotes/mysql/");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://legalhackers.com/advisories/MySQL-Exploit-Remote-Root-Code-Execution-Privesc-CVE-2016-6662.txt");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40360/");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed", "Host/runs_unixoide");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!sqlPort = get_app_port(cpe:CPE)){
  CPE = "cpe:/a:mysql:mysql";
  if(!sqlPort = get_app_port(cpe:CPE)){
    exit(0);
  }
}

if(!mysqlVer = get_app_version(cpe:CPE, port:sqlPort)){
  exit(0);
}

if(mysqlVer =~ "^(5\.5)")
{
  if(version_is_less(version:mysqlVer, test_version:"5.5.52"))
  {
    fix = "5.5.52";
    VULN = TRUE;
  }
}

else if(mysqlVer =~ "^(5\.6)")
{
  if(version_is_less(version:mysqlVer, test_version:"5.6.33"))
  {
    fix = "5.6.33";
    VULN = TRUE;
  }
}

else if(mysqlVer =~ "^(5\.7)")
{
  if(version_is_less(version:mysqlVer, test_version:"5.7.15"))
  {
    fix = "5.7.15";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:mysqlVer, fixed_version: fix);
  security_message(data:report, port:sqlPort);
  exit(0);
}
