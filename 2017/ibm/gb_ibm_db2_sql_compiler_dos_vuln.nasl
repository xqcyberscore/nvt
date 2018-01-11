###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_db2_sql_compiler_dos_vuln.nasl 8367 2018-01-11 07:32:43Z cfischer $
#
# IBM DB2 SQL Compiler Denial of Service Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812269");
  script_version("$Revision: 8367 $");
  script_cve_id("CVE-2014-3095");
  script_bugtraq_id(69546);
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-01-11 08:32:43 +0100 (Thu, 11 Jan 2018) $");
  script_tag(name:"creation_date", value:"2017-12-15 15:44:32 +0530 (Fri, 15 Dec 2017)");
  script_name("IBM DB2 SQL Compiler Denial of Service Vulnerability");

  script_tag(name: "summary" , value:"This host is running IBM DB2 and is
  prone to denial of service vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version of IBM DB2
  with the help of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to an improper
  handling of SELECT statement in SQL engine.");

  script_tag(name: "impact" , value:"Successful exploitation will allow an 
  attacker to cause the application to crash, resulting in denial-of-service 
  conditions.

  Impact Level: Application");

  script_tag(name: "affected" , value:"IBM DB2 9.5 through FP10, 9.7 through 
  FP9a, 9.8 through FP5, 10.1 through FP4, and 10.5 before FP4.");

  script_tag(name: "solution" , value:"Apply the appropriate fix from reference link");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21681623");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_remote_detect.nasl");
  script_mandatory_keys("IBM-DB2/installed");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

## Variable Initialization
ibmVer  = "";
ibmPort = "";
fix = "";

if(!ibmPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location( cpe:CPE, port:ibmPort, exit_no_version:TRUE)) exit(0);
ibmVer = infos['version'];
path = infos['location'];

if(ibmVer =~ "^1005\.*")
{
  ## IBM DB2 10.5 before FP4
  if(version_is_less(version:ibmVer, test_version:"10054")){
    fix  = "IBM DB2 10.5 FP4";
  }
}

else if(ibmVer =~ "^1001\.*")
{
  ## IBM DB2 10.1 before FP5
  if(version_is_less(version:ibmVer, test_version:"10015")){
    fix  = "IBM DB2 10.1 FP5";
  }
}

else if(ibmVer =~ "^0907\.*")
{

  ## IBM DB2 9.7 before FP10
  if(version_is_less(version:ibmVer, test_version:"090710")){
    fix  = "IBM DB2 9.7 FP10";
  }
}

else if(ibmVer =~ "^0908\.*") ##
{
  ## A special build with an interim patch for this issue may be requested.
  if(version_is_less_equal(version:ibmVer, test_version:"09085")){
    fix  = "Apply the appropriate patch from vendor";
  }
}

else if(ibmVer =~ "^0905\.*")
{
  ## A special build with an interim patch for this issue may be requested.
  if(version_is_less_equal(version:ibmVer, test_version:"090510")){
    fix  = "Apply the appropriate patch from vendor";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:ibmVer, fixed_version:fix, install_path:path);
  security_message(data:report, port:ibmPort);
  exit(0);
}

exit(0);
