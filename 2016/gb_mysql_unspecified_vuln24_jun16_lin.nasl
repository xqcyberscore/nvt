###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_unspecified_vuln24_jun16_lin.nasl 11545 2018-09-21 20:43:34Z cfischer $
#
# Oracle MySQL Multiple Unspecified Vulnerabilities-24 Jun16 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.808136");
  script_version("$Revision: 11545 $");
  script_cve_id("CVE-2015-2571", "CVE-2015-0505", "CVE-2015-0501", "CVE-2015-0499");
  script_bugtraq_id(74095, 74112, 74070, 74115);
  script_tag(name:"cvss_base", value:"5.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:M/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-21 22:43:34 +0200 (Fri, 21 Sep 2018) $");

  script_tag(name:"creation_date", value:"2016-06-03 13:42:20 +0530 (Fri, 03 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Oracle MySQL Multiple Unspecified Vulnerabilities-24 Jun16 (Linux)");

  script_tag(name:"summary", value:"This host is running Oracle MySQL and is
  prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unspecified errors in the MySQL Server
  component via unknown vectors related to Server : Optimizer, DDL,
  Server : Compiling, Server : Federated.");

  script_tag(name:"impact", value:"Successful exploitation will allows an
  authenticated remote attacker to cause a denial of service.");

  script_tag(name:"affected", value:"Oracle MySQL Server 5.5.42 and earlier,
  and 5.6.23 and earlier on Linux.");

  script_tag(name:"solution", value:"Apply the patch from below link,

  http://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html");

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

if(!sqlPort = get_app_port(cpe:CPE))
{
  CPE = "cpe:/a:mysql:mysql";
  if(!sqlPort = get_app_port(cpe:CPE)){
    exit(0);
  }
}

if(!mysqlVer = get_app_version(cpe:CPE, port:sqlPort)){
  exit(0);
}

if(mysqlVer =~ "^5\.[56]")
{
  if(version_in_range(version:mysqlVer, test_version:"5.5", test_version2:"5.5.42")||
     version_in_range(version:mysqlVer, test_version:"5.6", test_version2:"5.6.23"))
  {
    report = 'Installed version: ' + mysqlVer + '\n';
    security_message(data:report, port:sqlPort);
    exit(0);
  }
}

exit(99);