###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_kb4103725.nasl 10307 2018-06-25 05:05:34Z asteins $
#
# Microsoft Windows Multiple Vulnerabilities (KB4103725)
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
  script_oid("1.3.6.1.4.1.25623.1.0.813338");
  script_version("$Revision: 10307 $");
  script_cve_id("CVE-2018-0954", "CVE-2018-0955", "CVE-2018-0959", "CVE-2018-1022", 
                "CVE-2018-1025", "CVE-2018-8114", "CVE-2018-8122", "CVE-2018-8124", 
                "CVE-2018-8127", "CVE-2018-8134", "CVE-2018-8136", "CVE-2018-8145", 
                "CVE-2018-8164", "CVE-2018-8166", "CVE-2018-8167", "CVE-2018-8174", 
                "CVE-2018-8178", "CVE-2018-8897", "CVE-2018-0824", "CVE-2018-0886",
                "CVE-2017-11927");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-06-25 07:05:34 +0200 (Mon, 25 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-05-09 08:59:54 +0530 (Wed, 09 May 2018)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4103725)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4103725");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Multiple flaw exists due to,
  
  - Microsoft browsers improperly access objects in memory.

  - The Win32k component fails to properly handle objects in memory.

  - Windows kernel fails to properly handle objects in memory.

  - The VBScript engine improperly handles objects in memory.

  - The scripting engine improperly handles objects in memory in Microsoft browsers.

  - Windows Common Log File System (CLFS) driver improperly handles objects in memory.

  - Chakra improperly discloses the contents of its memory.

  - Windows Hyper-V on a host server fails to properly validate input from an
    authenticated user on a guest operating system.

  - Windows 'its://' protocol handler unnecessarily sends traffic to a remote site
    in order to determine the zone of a provided URL.

  - An error in Credential Security Support Provider protocol (CredSSP).");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to gain the same user rights as the current user, run arbitrary
  code, disclose sensitive information and run processes in an elevated context
  and it may lead to further compromise of the system.

  Impact Level: System");

  script_tag(name:"affected", value:"

  Microsoft Windows 8.1 for 32-bit/x64

  Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the Reference link.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/help/4103725");
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

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath, file_name:"mshtml.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"11.0.9600.19003"))
{
  report = report_fixed_ver(file_checked:sysPath + "\mshtml.dll",
                            file_version:fileVer, vulnerable_range:"Less than 11.0.9600.19003");
  security_message(data:report);
  exit(0);
}
exit(99);
