###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_mysqld_mult_dos_vuln.nasl 3386 2016-05-25 19:06:55Z jan $
#
# MySQL Mysqld Multiple Denial Of Service Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow users to cause a Denial of Service
  condution.
  Impact Level: Application";
tag_affected = "MySQL version 5.1 before 5.1.49 and 5.0 before 5.0.92 on all running platform.";
tag_insight = "The flaws are due to:
  - An error in handling of a join query that uses a table with a unique
    SET column.
  - An error in handling of 'EXPLAIN' with crafted 
   'SELECT ... UNION ... ORDER BY (SELECT ... WHERE ...)' statements.";
tag_solution = "Upgrade to MySQL version 5.1.49 or 5.0.92
  For updates refer to http://dev.mysql.com/downloads";
tag_summary = "The host is running MySQL and is prone to multiple denial of service
  vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801567";
CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3386 $");
  script_tag(name:"last_modification", value:"$Date: 2016-05-25 21:06:55 +0200 (Wed, 25 May 2016) $");
  script_tag(name:"creation_date", value:"2011-01-18 07:48:41 +0100 (Tue, 18 Jan 2011)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_cve_id("CVE-2010-3677", "CVE-2010-3682");
  script_name("MySQL Mysqld Multiple Denial Of Service Vulnerabilities");
  script_xref(name : "URL" , value : "http://bugs.mysql.com/bug.php?id=54477");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=628172");
  script_xref(name : "URL" , value : "http://dev.mysql.com/doc/refman/5.1/en/news-5-1-49.html");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/09/28/10");

  script_summary("Check for the version of MySQL");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_require_keys("MySQL/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("misc_func.inc");
include("version_func.inc");
include("global_settings.inc");
include("host_details.inc");

sqlPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!sqlPort){
  sqlPort = 3306;
}

if(!get_port_state(sqlPort)){
  exit(0);
}

mysqlVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:sqlPort);
if(isnull(mysqlVer)){
  exit(0);
}

mysqlVer = eregmatch(pattern:"([0-9.a-z]+)", string:mysqlVer);
if(!isnull(mysqlVer[1]))
{
  if(version_in_range(version:mysqlVer[1], test_version:"5.0",test_version2:"5.0.91")||
     version_in_range(version:mysqlVer[1], test_version:"5.1",test_version2:"5.1.48")){
    security_message(sqlPort);
  }
}
