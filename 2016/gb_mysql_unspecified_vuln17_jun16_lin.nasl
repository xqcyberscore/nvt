###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_unspecified_vuln17_jun16_lin.nasl 36954 2014-05-08 13:14:08Z may$
#
# Oracle MySQL Multiple Unspecified Vulnerabilities - 16 Jun16 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.808129");
  script_version("$Revision: 7572 $");
  script_cve_id("CVE-2014-2430", "CVE-2014-2431", "CVE-2014-2436", "CVE-2014-2440");
  script_bugtraq_id(66858, 66890, 66896, 66850);
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 10:08:35 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2016-06-03 13:42:48 +0530 (Fri, 03 Jun 2016)");
  script_name("Oracle MySQL Multiple Unspecified Vulnerabilities - 16 Jun16 (Linux)");

  script_tag(name : "summary" , value : "This host is running Oracle MySQL
  and is prone to multiple unspecified vulnerabilities.");

  script_tag(name : "vuldetect" , value : "Get the installed version with
  the help of detect NVT and check the version is vulnerable or not.");

  script_tag(name : "insight" , value : "Unspecified errors in the MySQL
  Server component via unknown vectors related to Performance Schema,Options,RBR.");

  script_tag(name : "impact" , value : "Successful exploitation will allow
  attackers to manipulate certain data and cause a DoS (Denial of Service).

  Impact Level: Application");

  script_tag(name : "affected" , value : "Oracle MySQL version 5.5.36 and earlier
  and 5.6.16 and earlier on Linux.");

  script_tag(name:"solution", value:"Apply the patch from below link,
  http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/57940");
  script_xref(name : "URL" , value : "http://www.scaprepo.com/view.jsp?id=oval:org.secpod.oval:def:701638");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Databases");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
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
  if(version_in_range(version:mysqlVer, test_version:"5.5", test_version2:"5.5.36")||
     version_in_range(version:mysqlVer, test_version:"5.6", test_version2:"5.6.16"))
  {
    security_message(sqlPort);
    exit(0);
  }
}
