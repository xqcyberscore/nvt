###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_kb4457426.nasl 11362 2018-09-12 13:37:01Z santu $
#
# Microsoft Internet Explorer Multiple Vulnerabilities (KB4457426)
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
  script_oid("1.3.6.1.4.1.25623.1.0.814001");
  script_version("$Revision: 11362 $");
  script_cve_id("CVE-2018-8447", "CVE-2018-8452", "CVE-2018-8315", "CVE-2018-8457",
                "CVE-2018-8470");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-12 15:37:01 +0200 (Wed, 12 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-12 09:30:00 +0530 (Wed, 12 Sep 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (KB4457426)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft security updates KB4457426.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Internet Explorer improperly handles objects in memory.

  - Scripting engine improperly handles objects in memory.

  - Internet Explorer improperly handles scripts.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code in the context of the current user, access any session
  belonging to web pages currently opened (or cached) by the browser and disclose
  sensitive information.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 9.x, 10.x
  and 11.x");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the Reference link");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-gb/help/4457426");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2008:3, win2008x64:3, win2012:1, win7:2, win7x64:2,
                   win2008r2:2, win8_1:1, win8_1x64:1, win2012R2:1) <= 0){
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
  if(version_is_less(version:iedllVer, test_version:"9.0.8112.21261")){
    Vulnerable_range = "Less than 9.0.8112.21261";
  }
}

else if(hotfix_check_sp(win2012:1) > 0)
{
  if(version_in_range(version:iedllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.22549")){
    Vulnerable_range = "10.0.9200.16000 - 10.0.9200.22549";
  }
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_in_range(version:iedllVer, test_version:"11.0.9600.00000", test_version2:"11.0.9600.19129")){
    Vulnerable_range = "11.0.9600.00000 - 11.0.9600.19129";
  }
}

if(Vulnerable_range)
{
  report = report_fixed_ver(file_checked:iePath + "\Mshtml.dll",
                            file_version:iedllVer, vulnerable_range:Vulnerable_range);
  security_message(data:report);
}
exit(0);
