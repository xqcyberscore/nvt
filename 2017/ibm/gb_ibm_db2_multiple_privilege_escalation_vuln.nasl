###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_db2_multiple_privilege_escalation_vuln.nasl 10258 2018-06-19 14:17:42Z cfischer $
#
# IBM DB2 Multiple Privilege Escalation Vulnerabilities
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811693");
  script_version("$Revision: 10258 $");
  script_cve_id("CVE-2017-1520", "CVE-2017-1451", "CVE-2017-1452", "CVE-2017-1439",
                "CVE-2017-1438");
  script_bugtraq_id(100684, 100690, 100698, 100685);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-09-25 07:48:36 +0200 (Mo, 25 Sep 2017)$");
  script_tag(name:"creation_date", value:"2017-09-14 12:39:29 +0530 (Thu, 14 Sep 2017)");
  script_name("IBM DB2 Multiple Privilege Escalation Vulnerabilities");

  script_tag(name:"summary", value:"This host is running IBM DB2 and is
  prone to multiple privilege escalation vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version of IBM DB2
  with the help of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An unauthorized command that allows the database to be activated when
    authentication type is CLIENT.

  - Multiple errors in validating privileges of local users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to obtain root access and a user without proper authority can activate database.

  Impact Level: Application");

  script_tag(name:"affected", value:"

  IBM DB2 versions 9.7 before 9.7 FP11,

  IBM DB2 versions 10.1 before 10.1 FP6,

  IBM DB2 versions 10.5 before 10.5 FP8,

  IBM DB2 versions 11.1.2.2 before 11.1.2.2 FP2");

  script_tag(name:"solution", value:"Apply the appropriate fix from reference links");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22006109");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22007186");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22006885");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22006061");
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

if(!ibmPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ibmVer = get_app_version(cpe:CPE, port:ibmPort)){
  exit(0);
}

if(ibmVer =~ "^0907\.*"){
  ## IBM DB2 9.7 before FP11
  ## IBM DB2 9.7 FP11 => 090711
  if(version_is_less(version:ibmVer, test_version:"090711")){
    fix = "IBM DB2 9.7 FP11";
  }
}

else if(ibmVer =~ "^1001\.*"){
  ## IBM DB2 10.1 before FP6
  ## IBM DB2 10.1 FP6  => 10016
  if(version_is_less(version:ibmVer, test_version:"10016")){
    fix = "IBM DB2 10.1 FP6";
  }
}

else if(ibmVer =~ "^1005\.*"){
  ## IBM DB2 10.5 before FP8
  ## IBM DB2 10.5 FP8 => 10058
  if(version_is_less(version:ibmVer, test_version:"10058")){
    fix = "IBM DB2 10.5 FP8";
  }
}

else if(ibmVer =~ "^110122\.*"){
  ## IBM DB2 11.1.2.2 before FP2
  ## IBM DB2 11.1.2.2 FP2 => 1101222
  if(version_is_less(version:ibmVer, test_version:"1101222")){
    fix = "IBM DB2 11.1.2.2 FP2";
  }
}

if(fix){
  report = report_fixed_ver(installed_version:ibmVer, fixed_version:fix);
  security_message(data:report, port:ibmPort);
  exit(0);
}

exit(99);