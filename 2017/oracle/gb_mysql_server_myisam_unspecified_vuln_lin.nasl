###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_server_myisam_unspecified_vuln_lin.nasl 7905 2017-11-24 12:58:24Z santu $
#
# MySQL Server Component MyISAM Unspecified Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812181");
  script_version("$Revision: 7905 $");
  script_cve_id("CVE-2012-0583");
  script_bugtraq_id(53061);
  script_tag(name:"last_modification", value:"$Date: 2017-11-24 13:58:24 +0100 (Fri, 24 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-23 14:56:52 +0530 (Thu, 23 Nov 2017)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_name("MySQL Server Component MyISAM Unspecified Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48890");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpuapr2012-366314.html#AppendixMSQL");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed","Host/runs_unixoide");

  script_tag(name : "impact" , value : "Successful exploitation could allow
  remote authenticated users to affect availability via unknown vectors.

  Impact Level: Application");

  script_tag(name : "affected" , value : "MySQL version 5.1.x before 5.1.61 and
  5.5.x before 5.5.20");

  script_tag(name : "insight" , value : "Unspecified error in MySQL Server
  component related to MyISAM.");

  script_tag(name : "solution" , value : "Apply the patch from the below link,
  http://www.oracle.com/technetwork/topics/security/cpuapr2012-366314.html");

  script_tag(name : "summary" , value : "The host is running MySQL and is prone
  to unspecified vulnerability.");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

sqlPort = "";
mysqlVer = "";

sqlPort = get_app_port(cpe:CPE);
if(!sqlPort){
  sqlPort = 3306;
}

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
mysqlVer = infos['version'];
mysqlPath = infos['location'];

if(mysqlVer && mysqlVer =~ "^(5\.(1|5))")
{
  if(version_in_range(version:mysqlVer, test_version:"5.1", test_version2:"5.1.60") ||
     version_in_range(version:mysqlVer, test_version:"5.5", test_version2:"5.5.19"))
  {
    report = report_fixed_ver( installed_version:mysqlVer, fixed_version: "Apply the patch", install_path:mysqlPath );
    security_message(sqlPort);
    exit(0);
  }
}
