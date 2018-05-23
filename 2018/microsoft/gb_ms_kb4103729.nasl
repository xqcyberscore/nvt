###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_kb4103729.nasl 9919 2018-05-22 12:05:34Z jschulte $
#
# Adobe Flash Security Update May18 (KB4103729)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813353");
  script_version("$Revision: 9919 $");
  script_cve_id("CVE-2018-4944");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-05-22 14:05:34 +0200 (Tue, 22 May 2018) $");
  script_tag(name:"creation_date", value:"2018-05-09 12:25:07 +0530 (Wed, 09 May 2018)");
  script_name("Adobe Flash Security Update May18 (KB4103729)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4103729");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name: "insight" , value:"The flaw exists due to a type confusion
  error.");

  script_tag(name: "impact" , value:"Successful exploitation will allow
  attackers to conduct arbitrary code execution.

  Impact Level: System");

  script_tag(name:"affected", value:"

  Microsoft Windows 10 Version 1703 x32/x64

  Windows 10 Version 1803 for 32-bit Systems

  Windows 10 Version 1803 for x64-based Systems

  Windows 10 Version 1709 for 32-bit Systems

  Windows 10 Version 1709 for 64-based Systems

  Windows 10 for 32-bit Systems

  Windows 10 for x64-based Systems

  Microsoft Windows 10 Version 1607 x32/x64

  Microsoft Windows Server 2016

  Microsoft Windows 8.1 for 32-bit/x64

  Microsoft Windows Server 2012

  Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the Reference link.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/help/4103729");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1, win2016:1, win8_1:1, win8_1x64:1, win2012:1, win2012R2:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath, file_name:"flashplayerapp.exe");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"29.0.0.171"))
{
  report = report_fixed_ver(file_checked:sysPath + "\flashplayerapp.exe",
                            file_version:fileVer, vulnerable_range:"Less than 29.0.0.171");
  security_message(data:report);
  exit(0);
}

exit(99);
