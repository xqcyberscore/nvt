###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trendmicro_internet_security_mult_vuln.nasl 8199 2017-12-20 13:37:22Z cfischer $
#
# TrendMicro Internet Security Multiple Vulnerabilities
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

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:trendmicro:internet_security";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808638");
  script_version("$Revision: 8199 $");
  script_cve_id("CVE-2016-1225", "CVE-2016-1226");
  script_bugtraq_id(90999);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-20 14:37:22 +0100 (Wed, 20 Dec 2017) $");
  script_tag(name:"creation_date", value:"2016-08-05 12:51:56 +0530 (Fri, 05 Aug 2016)");
  script_name("TrendMicro Internet Security Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with TrendMicro Internet
  Security and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The multiple flaws are due to multiple input 
  validation errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to access files on the device and also to execute arbitrary script
  on the products.

  Impact Level: Application");

  script_tag(name:"affected", value:"TrendMicro Internet Security version 8 and 10");

  script_tag(name:"solution", value:"Apply the patch from the below link
  https://esupport.trendmicro.com/support/vb/solution/ja-jp/1113880.aspx");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "http://jvn.jp/en/jp/JVN48789425/index.html");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_trendmicro_internet_security_detect.nasl");
  script_mandatory_keys("TrendMicro/IS/Installed");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );

treVer = infos['version'];
sysPath = infos['location'];
if( ! sysPath ) exit(0);

## Get plugDaemonHost.dll file version
sysVer = fetch_file_version(sysPath, file_name:"Titanium\plugin\plugDaemonHost.dll");
if(!sysVer){
  exit(0);
}

##Check for vulnerable version
if(version_is_equal(version:treVer, test_version:"8.0") ||
   version_is_equal(version:treVer, test_version:"10.0")) {
  ## Set Minimum Required Version
  if(treVer =~ "^8"){
    minRequireVer = "8.0.0.2062";
  } else {
    ## After installing version 10 gives 9.0.0.1265
    minRequireVer = "9.0.0.1265";
  }

  ## Checking fix already applied or not
  ## Check for the plugDaemonHost.dll version 
  if(version_is_less(version:sysVer, test_version:minRequireVer)) {
    report = report_fixed_ver(installed_version:treVer, fixed_version:"Apply the Patch", install_path:sysPath);
    security_message(data:report);
    exit(0);
  }
}

exit( 99 );