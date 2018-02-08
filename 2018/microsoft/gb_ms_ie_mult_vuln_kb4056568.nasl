###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_mult_vuln_kb4056568.nasl 8705 2018-02-07 15:38:30Z cfischer $
#
# Microsoft Internet Explorer Multiple Vulnerabilities (KB4056568)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:microsoft:ie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812289");
  script_version("$Revision: 8705 $");
  script_cve_id("CVE-2018-0762", "CVE-2018-0772", "CVE-2017-5753", "CVE-2017-5715",
                "CVE-2017-5754");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-02-07 16:38:30 +0100 (Wed, 07 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-01-04 13:38:43 +0530 (Thu, 04 Jan 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (KB4056568)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft security updates KB4056568");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - A new publicly disclosed class of vulnerabilities referred to as
    'speculative execution side-channel attacks' that affect many modern
    processors and operating systems including Intel, AMD, and ARM.

  - Multiple errors exists in the way the scripting engine handles objects in
    memory in Microsoft browsers.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code in the context of the current user, gain the same
  user rights as the current user, take control of an affected system and can
  read the content of memory therefore lead to information disclosure, conduct
  bounds check bypass, branch target injection and rogue data cache load, and
  some unspecified impacts too.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Microsoft Internet Explorer version 9.x,
  10.x and 11.x");

  script_tag(name: "solution" , value:"Run Windows Update and update the listed
  hotfixes or download and update mentioned hotfixes in the advisory from the
  https://support.microsoft.com/en-us/help/4056568");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/help/4056568");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

iePath = "";
iedllVer  = NULL;

if(hotfix_check_sp(win2008:3, win2008x64:3, win7:2, win7x64:2, win2008r2:2, win2012:1,  win2012R2:1,
                   win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

ieVer = get_app_version(cpe:CPE);
if(!ieVer || !(ieVer =~ "^(9|10|11)")){
  exit(0);
}

iePath = smb_get_system32root();
if(!iePath ){
  exit(0);
}

iedllVer = fetch_file_version(sysPath:iePath, file_name:"Mshtml.dll");
if(!iedllVer){
  exit(0);
}

if(hotfix_check_sp(win2008:3, win2008x64:3) > 0)
{
  if(version_is_less(version:iedllVer, test_version:"9.0.8112.21097")){
    Vulnerable_range = "Less than 9.0.8112.21097";
  }
}

else if(hotfix_check_sp(win2012:1) > 0)
{
  if(version_is_less(version:iedllVer, test_version:"10.0.9200.22332")){
    Vulnerable_range = "Less than 10.0.9200.22332";
  }
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1, win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:iedllVer, test_version:"11.0.9600.18879")){
     Vulnerable_range = "Less than 11.0.9600.18879";
  }
}

if(Vulnerable_range)
{
  report = report_fixed_ver(file_checked:iePath + "\Mshtml.dll",
                            file_version:iedllVer, vulnerable_range:Vulnerable_range);
  security_message(data:report);
  exit(0);
}
exit(0);
