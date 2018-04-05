###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_db2_untrusted_search_path_vuln.nasl 9300 2018-04-04 11:55:01Z cfischer $
#
# IBM DB2 Untrusted Search Path Vulnerability
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809431");
  script_version("$Revision: 9300 $");
  script_cve_id("CVE-2016-5995");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-04 13:55:01 +0200 (Wed, 04 Apr 2018) $");
  script_tag(name:"creation_date", value:"2016-10-04 17:08:20 +0530 (Tue, 04 Oct 2016)");
  script_name("IBM DB2 Untrusted Search Path Vulnerability");

  script_tag(name: "summary" , value:"This host is running IBM DB2 and is
  prone to untrusted search path vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version of IBM DB2
  with the help of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to loading libraries
  from insecure locations.");

  script_tag(name: "impact" , value:"Successful exploitation will allow local
  user to gain elevated privilege.

  Impact Level: Application");

  script_tag(name: "affected" , value:"
  IBM DB2 versions 9.7 through FP11
  IBM DB2 versions 10.1 through FP5
  IBM DB2 versions 10.5 through FP7");

  script_tag(name: "solution" , value:"Apply the appropriate fix from below link,
  http://www-01.ibm.com/support/docview.wss?uid=swg21990061");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21990061");

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

if(!ibmPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ibmVer = get_app_version(cpe:CPE, port:ibmPort)){
  exit(0);
}

##Check for IBM DB2 9.7 through FP11
if(ibmVer =~ "^0907\.*"){
  ## IBM DB2 9.7 through FP11
  ## IBM DB2 9.7 FP11 => 090711
  if(version_is_less_equal(version:ibmVer, test_version:"090711")){
    VULN = TRUE;
  }
}
##Only Enterprise Server Edition V9.8 is vulnerable
##Not considering that, as no way to confirm that

##Check for IBM DB2 10.1 through FP5
if(ibmVer =~ "^1001\.*"){
  ## IBM DB2 10.1 through FP5
  ## IBM DB2 10.1 FP5  => 10015
  if(version_is_less_equal(version:ibmVer, test_version:"10015")){
    VULN = TRUE;
  }
}

##Check for IBM DB2 10.5 through FP7
if(ibmVer =~ "^1005\.*"){
  ## IBM DB2 10.5 through FP7
  ## IBM DB2 10.5 FP7 => 10057
  if(version_is_less_equal(version:ibmVer, test_version:"10057")){
    VULN = TRUE;
  }
}

if(VULN){
  report = report_fixed_ver(installed_version:ibmVer, fixed_version:"Apply appropriate fix");
  security_message(port:ibmPort, data:report);
  exit(0);
}

exit(99);