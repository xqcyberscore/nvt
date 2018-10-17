###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_dos_vuln_feb17_win.nasl 11936 2018-10-17 09:05:37Z mmartin $
#
# Oracle MySQL Denial Of Service Vulnerability Feb17 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.810603");
  script_version("$Revision: 11936 $");
  script_cve_id("CVE-2017-3302");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-17 11:05:37 +0200 (Wed, 17 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-16 14:35:00 +0530 (Thu, 16 Feb 2017)");
  script_name("Oracle MySQL Denial Of Service Vulnerability Feb17 (Windows)");

  script_tag(name:"summary", value:"This host is running Oracle MySQL and is
  prone to denial-of-service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple errors exists as,

  - In sql-common/client.c script 'mysql_prune_stmt_list' function, the for loop
    adds elements to pruned_list without removing it from the existing list.

  - If application gets disconnected just before it tries to prepare a new
    statement, 'mysql_prune_stmt_list' tries to detach all previously prepared
    statements.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow attackers to cause crash of applications using that MySQL client.");

  script_tag(name:"affected", value:"Oracle MySQL version before 5.6.21 and
  5.7.x before 5.7.5 on Windows");

  script_tag(name:"solution", value:"Upgrade to Oracle MySQL version 5.6.21 or
  5.7.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://bugs.mysql.com/bug.php?id=63363");
  script_xref(name:"URL", value:"https://bugs.mysql.com/bug.php?id=70429");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2017/02/11/11");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MySQL/installed", "Host/runs_windows");
  script_require_ports("Services/mysql", 3306);
  script_xref(name:"URL", value:"https://www.mysql.com");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sqlPort = get_app_port(cpe:CPE))
{
  CPE = "cpe:/a:mysql:mysql";
  if(!sqlPort = get_app_port(cpe:CPE)){
    exit(0);
  }
}

if( get_kb_item( "MySQL/" + sqlPort + "/blocked" ) ) exit( 0 );

if(!mysqlVer = get_app_version(cpe:CPE, port:sqlPort)){
  exit(0);
}

if(mysqlVer =~ "^(5\.7\.)")
{
  if(version_is_less(version:mysqlVer, test_version:"5.7.5"))
  {
    VULN = TRUE;
    fix = "5.7.5";
  }
}

else if(version_is_less(version:mysqlVer, test_version:"5.6.21"))
{
  VULN = TRUE;
  fix = "5.6.21";
}

if(VULN)
{
  report = report_fixed_ver(installed_version:mysqlVer, fixed_version: fix);
  security_message(data:report, port:sqlPort);
  exit(0);
}
