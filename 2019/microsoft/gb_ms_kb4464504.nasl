# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814956");
  script_version("2019-04-10T14:27:48+0000");
  script_cve_id("CVE-2019-0801");
  script_bugtraq_id(107738);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-04-10 14:27:48 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-10 11:11:24 +0530 (Wed, 10 Apr 2019)");
  script_name("Microsoft Office 2013 Service Pack 1 Remote Code Execution Vulnerability (KB4464504)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4464504");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists when Microsoft Office
  fails to properly handle certain files.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  execute arbitrary code in the context of the currently logged-in user. Failed
  exploit attempts will likely result in denial of service conditions.");

  script_tag(name:"affected", value:"Microsoft Office 2013 Service Pack 1");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the Reference link.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4464504");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

offVer = get_kb_item("MS/Office/Ver");
if(!offVer|| offVer !~ "^15\."){
  exit(0);
}

if(!os_arch = get_kb_item("SMB/Windows/Arch")){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion");
}
else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion",
                        "SOFTWARE\Microsoft\Windows\CurrentVersion");
}

foreach key(key_list)
{
  commonpath = registry_get_sz(key:key, item:"CommonFilesDir");
  if(!commonpath){
    continue;
  }

  offPath = commonpath + "\Microsoft Shared\Office15";
  offexeVer = fetch_file_version(sysPath:offPath, file_name:"Mso.dll");

  if(offexeVer && version_in_range(version:offexeVer, test_version:"15.0", test_version2:"15.0.5127.0999"))
  {
    report = report_fixed_ver(file_checked:offPath + "\Mso.dll",
                              file_version:offexeVer, vulnerable_range:"15.0 - 15.0.5127.0999");
    security_message(data:report);
    exit(0);
  }
}
exit(99);
