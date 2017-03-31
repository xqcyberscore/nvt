###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_mult_vuln.nasl 5323 2017-02-17 08:49:23Z teissa $
#
# MySQL Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow users to cause a denial of service and
  to execute arbitrary code.
  Impact Level: Application";
tag_affected = "MySQL 5.0.x before 5.0.91 and 5.1.x before 5.1.47 on all running platform.";
tag_insight = "The flaws are due to:
  - An error in 'my_net_skip_rest()' function in 'sql/net_serv.cc' when handling
    a large number of packets that exceed the maximum length, which allows remote
    attackers to cause a denial of service (CPU and bandwidth consumption).
  - buffer overflow when handling 'COM_FIELD_LIST' command with a long
    table name, allows remote authenticated users to execute arbitrary code.
  - directory traversal vulnerability when handling a '..' (dot dot) in a
    table name, which allows remote authenticated users to bypass intended
    table grants to read field definitions of arbitrary tables.";
tag_solution = "Upgrade to MySQL version 5.0.91 or 5.1.47,
  For updates refer to http://dev.mysql.com/downloads";
tag_summary = "The host is running MySQL and is prone to multiple vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801355";
CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5323 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-17 09:49:23 +0100 (Fri, 17 Feb 2017) $");
  script_tag(name:"creation_date", value:"2010-06-11 14:27:58 +0200 (Fri, 11 Jun 2010)");
  script_cve_id("CVE-2010-1848",  "CVE-2010-1849", "CVE-2010-1850");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_name("MySQL Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/May/1024031.html");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/May/1024033.html");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/May/1024032.html");
  script_xref(name : "URL" , value : "http://dev.mysql.com/doc/refman/5.1/en/news-5-1-47.html");
  script_xref(name : "URL" , value : "http://dev.mysql.com/doc/refman/5.0/en/news-5-0-91.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Databases");
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
  if(version_in_range(version:mysqlVer[1], test_version:"5.0",test_version2:"5.0.90") ||
     version_in_range(version:mysqlVer[1], test_version:"5.1",test_version2:"5.1.46")){
    security_message(sqlPort);
  }
}
