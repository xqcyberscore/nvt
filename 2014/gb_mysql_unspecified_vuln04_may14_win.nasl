###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_unspecified_vuln04_may14_win.nasl 36954 2014-05-08 13:35:09Z may$
#
# Oracle MySQL Multiple Unspecified vulnerabilities - 04 May14 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804577";
CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 7547 $");
  script_cve_id("CVE-2014-2435");
  script_bugtraq_id(66853);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 14:02:32 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"creation_date", value:"2014-05-08 13:35:09 +0530 (Thu, 08 May 2014)");
  script_name("Oracle MySQL Multiple Unspecified vulnerabilities - 04 May14 (Windows)");

  tag_summary =
"This host is running Oracle MySQL and is prone to multiple unspecified
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Unspecified errors in the MySQL Server component via unknown vectors related
to InnoDB.";

  tag_impact =
"Successful exploitation will allow attackers to manipulate certain data
and cause a DoS (Denial of Service).

Impact Level: Application";

  tag_affected =
"Oracle MySQL version 5.6.16 and earlier on Windows.";

  tag_solution =
"Apply the patch from below link,
http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/57940");
  script_xref(name : "URL" , value : "http://www.scaprepo.com/view.jsp?id=oval:org.secpod.oval:def:701638");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Databases");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
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

## Get Port
if(!sqlPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get version
if(!mysqlVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:sqlPort)){
  exit(0);
}

if(mysqlVer =~ "^(5\.6)")
{
  if(version_in_range(version:mysqlVer, test_version:"5.6", test_version2:"5.6.16"))
  {
    security_message(sqlPort);
    exit(0);
  }
}
