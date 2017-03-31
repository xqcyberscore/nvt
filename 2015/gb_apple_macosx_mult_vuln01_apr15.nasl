###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_mult_vuln01_apr15.nasl 3496 2016-06-13 12:01:56Z benallard $
#
# Apple Mac OS X Multiple Vulnerabilities-01 Apr15
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805601");
  script_version("$Revision: 3496 $");
  script_cve_id("CVE-2015-1130", "CVE-2015-1131", "CVE-2015-1132", "CVE-2015-1133",
                "CVE-2015-1134", "CVE-2015-1135", "CVE-2015-1136", "CVE-2015-1088",
                "CVE-2015-1089", "CVE-2015-1091", "CVE-2015-1093", "CVE-2015-1137",
                "CVE-2015-1138", "CVE-2015-1139", "CVE-2015-1140", "CVE-2015-1141",
                "CVE-2015-1142", "CVE-2015-1143", "CVE-2015-1144", "CVE-2015-1145",
                "CVE-2015-1146", "CVE-2015-1147", "CVE-2015-1148", "CVE-2015-1095",
                "CVE-2015-1098", "CVE-2015-1099", "CVE-2015-1100", "CVE-2015-1101",
                "CVE-2015-1102", "CVE-2015-1103", "CVE-2015-1104", "CVE-2015-1105",
                "CVE-2015-1117", "CVE-2015-1118");
  script_bugtraq_id(73982, 73984, 72328, 73981);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-06-13 14:01:56 +0200 (Mon, 13 Jun 2016) $");
  script_tag(name:"creation_date", value:"2015-04-24 15:41:40 +0530 (Fri, 24 Apr 2015)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-01 Apr15");

  script_tag(name: "summary" , value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws exists. For details refer
  reference section.");

  script_tag(name: "impact" , value:"Successful exploitation will allow local
  attacker to execute arbitrary code with system privilege, man-in-the-middle
  attack, remote attacker to bypass network filters, to cause a denial of
  service, a context-dependent attacker to corrupt memory and cause a denial of
  service,  bypass signature validation or potentially execute arbitrary code, a
  local application to gain elevated privileges by using a compromised service
  and some unspecified impacts.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Apple Mac OS X versions 10.8.5, 10.9.5,
  and 10.10.x through 10.10.2");

  script_tag(name: "solution" , value:"Upgrade to Apple Mac OS X version 10.10.3
  For more updates refer to https://www.apple.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name : "URL" , value : "https://support.apple.com/kb/HT204659");
  script_summary("Check for the vulnerable version of Apple Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
osName = "";
osVer = "";

## Get the OS name
osName = get_kb_item("ssh/login/osx_name");
if(!osName){
  exit (0);
}

## Get the OS Version
osVer = get_kb_item("ssh/login/osx_version");
if(!osVer){
 exit(0);
}

## Check for the Mac OS X
if("Mac OS X" >< osName)
{
  ## Check the affected OS versions
  if(version_is_equal(version:osVer, test_version:"10.8.5")||
     version_is_equal(version:osVer, test_version:"10.9.5")||
     version_in_range(version:osVer, test_version:"10.10.0", test_version2:"10.10.2"))
  {
    report = 'Installed Version: ' + osVer + '\nFixed Version: 10.10.3\n';
    security_message(data:report);
    exit(0);
  }
}
