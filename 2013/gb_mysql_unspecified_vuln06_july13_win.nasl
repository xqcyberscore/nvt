###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_unspecified_vuln06_july13_win.nasl 9984 2018-05-28 14:36:22Z cfischer $
#
# MySQL Unspecified vulnerability-06 July-2013 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803728");
  script_version("$Revision: 9984 $");
  script_cve_id("CVE-2013-3783");
  script_bugtraq_id(61210);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-05-28 16:36:22 +0200 (Mon, 28 May 2018) $");
  script_tag(name:"creation_date", value:"2013-07-30 10:33:07 +0530 (Tue, 30 Jul 2013)");
  script_name("MySQL Unspecified vulnerability-06 July-2013 (Windows)");


  script_tag(name : "summary" , value : "This host is running MySQL and is prone to unspecified vulnerability.");
  script_tag(name : "vuldetect" , value : "Get the installed version of MySQL with the help of detect NVT and
check it is vulnerable or not.");
  script_tag(name : "solution" , value : "Apply the patch from below link,
http://www.oracle.com/technetwork/topics/security/cpujuly2013-1899826.html ");
  script_tag(name : "insight" , value : "Unspecified error in the MySQL Server component via unknown vectors related
to Server Parser.");
  script_tag(name : "affected" , value : "Oracle MySQL 5.5.31 and earlier on Windows");
  script_tag(name : "impact" , value : "Successful exploitation will allow remote authenticated users to affect
availability via unknown vectors.

  Impact Level: Application");

  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpujuly2013-1899826.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Databases");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed","Host/runs_windows");
  exit(0);
}

include("misc_func.inc");
include("version_func.inc");
include("host_details.inc");

if(!sqlPort = get_app_port(cpe:CPE)) exit(0);
mysqlVer = get_app_version(cpe:CPE, port:sqlPort);

if(mysqlVer && mysqlVer =~ "^(5\.5)")
{
  if(version_in_range(version:mysqlVer, test_version:"5.5", test_version2:"5.5.31"))
  {
    security_message(sqlPort);
    exit(0);
  }
}
