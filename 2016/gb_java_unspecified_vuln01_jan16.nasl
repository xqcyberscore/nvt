###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_java_unspecified_vuln01_jan16.nasl 5675 2017-03-22 10:00:52Z teissa $
#
# Oracle Java SE JRE Unspecified Vulnerability-01 Jan 2016 (Windows)
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

CPE = "cpe:/a:oracle:jre";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806670");
  script_version("$Revision: 5675 $");
  script_cve_id("CVE-2016-0475");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-22 11:00:52 +0100 (Wed, 22 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-01-22 16:24:06 +0530 (Fri, 22 Jan 2016)");
  script_name("Oracle Java SE JRE Unspecified Vulnerability-01 Jan 2016 (Windows)");

  script_tag(name: "summary" , value:"The host is installed with Oracle Java SE
  JRE and is prone to unspecified vulnerability..");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to some unspecified
  error.");

  script_tag(name: "impact" , value:"Successful exploitation will allow attackers
  to have an impact on confidentiality and integrity via unknown vectors.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Oracle Java SE 8 update 66 and prior on
  Windows.");

  script_tag(name: "solution" , value:"Apply the patch from below link,
  http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
jreVer = "";

## Get version
if(!jreVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(jreVer =~ "^(1\.8)")
{
  jreVer = ereg_replace(pattern:"[a-z]+_|-", string:jreVer, replace: ".");

  ##Check for Oracle Java SE Versions
  if(version_in_range(version:jreVer, test_version:"1.8.0", test_version2:"1.8.0.66"))
  {
    report = 'Installed version: ' + jreVer + '\n' +
             'Fixed version:     ' + "Apply the patch"  + '\n';
    security_message(data:report);
    exit(0);
  }
}
