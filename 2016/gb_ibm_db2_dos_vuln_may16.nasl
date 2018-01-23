###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_db2_dos_vuln_may16.nasl 8473 2018-01-19 15:49:03Z gveerendra $
#
# IBM DB2 LUW Multiple Denial of Service Vulnerabilities - May16
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807815");
  script_version("$Revision: 8473 $");
  script_cve_id("CVE-2016-0211", "CVE-2016-0215");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-01-19 16:49:03 +0100 (Fri, 19 Jan 2018) $");
  script_tag(name:"creation_date", value:"2016-05-02 14:34:01 +0530 (Mon, 02 May 2016)");
  script_name("IBM DB2 LUW Multiple Denial of Service Vulnerabilities - May16");

  script_tag(name: "summary" , value:"This host is running IBM DB2 and is
  prone to multiple denial of service vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version of IBM DB2
  with the help of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to some unspecified
  error within application, while handling specially-crafted DRDA messages and
  specially-crafted SELECT statement with subquery containing the AVG OLAP 
  function.");

  script_tag(name: "impact" , value:"Successful exploitation will allow attacker
  to terminate abnormally the application causing a denial of service condition.

  Impact Level: Application");

  script_tag(name: "affected" , value:"
  IBM DB2 versions 9.7 through FP11
  IBM DB2 versions 10.1 through FP5
  IBM DB2 versions 10.5 through FP7");

  script_tag(name: "solution" , value:"Apply the appropriate fix from below links,
  http://www-01.ibm.com/support/docview.wss?uid=swg21979984
  http://www-01.ibm.com/support/docview.wss?uid=swg21979986");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21979984");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21979986");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_remote_detect.nasl");
  script_mandatory_keys("IBM-DB2/installed");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

ibmVer  = "";
ibmPort = "";

if(!ibmPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ibmVer = get_app_version(cpe:CPE, port:ibmPort)){
  exit(0);
}

if(ibmVer =~ "^0907\.*")
{
  if(version_is_less_equal(version:ibmVer, test_version:"090711")){
    VULN = TRUE;
  }
}
if(ibmVer =~ "^1001\.*")
{
  if(version_is_less_equal(version:ibmVer, test_version:"10015")){
    VULN = TRUE;
  }
}

if(ibmVer =~ "^1005\.*")
{
  if(version_is_less_equal(version:ibmVer, test_version:"10057")){
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:ibmVer, fixed_version:"Apply appropriate fix");
  security_message(data:report);
  exit(0);
}
