###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms14-011.nasl 9487 2018-04-16 05:40:30Z cfischer $
#
# Microsoft VBScript Remote Code Execution Vulnerability (2928390)
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2014 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903229");
  script_version("$Revision: 9487 $");
  script_cve_id("CVE-2014-0271");
  script_bugtraq_id(65395);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-16 07:40:30 +0200 (Mon, 16 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-02-12 09:18:06 +0530 (Wed, 12 Feb 2014)");
  script_name("Microsoft VBScript Remote Code Execution Vulnerability (2928390)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl", "gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56796");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2928390");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms14-011");

  script_tag(name:"summary", value:"This host is missing an critical security update according to Microsoft
  Bulletin MS14-011.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and check appropriate patch is applied
  or not.");

  script_tag(name:"insight", value:"Flaw is due to improper handling of memory objects in VBScript engine.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code and
  corrupt memory.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Microsoft Windows XP Service Pack 3 and prior

  Microsoft Windows XP x64 Edition Service Pack 2 and prior

  Microsoft Windows 2003 x32 Pack 3 and prior

  Microsoft Windows 2003 x64 Service Pack 2 and prior

  Microsoft Windows Vista x32/x64 Service Pack 2 and prior

  Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior

  Microsoft Windows 7 x32/x64 Service Pack 1 and prior

  Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior

  Microsoft Windows 8 x32/x64

  Microsoft Windows 8.1 x32/x64

  Microsoft Windows Server 2012

  Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,

  https://technet.microsoft.com/en-us/security/bulletin/ms14-011");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, winVistax64:3,
                   win7:2, win7x64:2, win2008:3, win2008x64:3, win2008r2:2,
                   win8:1, win8x64:1, win2012:1, win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

ieVer = get_app_version(cpe:CPE);
if(!ieVer || !(ieVer =~ "^(6|7|8|9|10|11)")){
  exit(0);
}

sysVer = fetch_file_version(sysPath, file_name:"system32\Vbscript.dll");
if(!sysVer){
  exit(0);
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0){
  if(version_is_less(version:sysVer, test_version:"5.7.6002.23292") ||
    (ieVer =~ "^8" && version_in_range(version:sysVer, test_version:"5.8", test_version2:"5.8.6001.23551"))){
    report = report_fixed_ver(file_checked:sysPath + "system32\Vbscript.dll", file_version:sysVer, vulnerable_range:"< 5.7.6002.23292, 5.8 - 5.8.6001.23551");
    security_message(port:0, data:report);
  }
  exit(0);
}

## Windows 2003 x86, Windows XP x64 and Windows 2003 x64
else if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0){
  if(version_is_less(version:sysVer, test_version:"5.6.0.8852") ||
     version_in_range(version:sysVer, test_version:"5.7", test_version2:"5.7.6002.23291") ||
     (ieVer =~ "^8" && version_in_range(version:sysVer, test_version:"5.8", test_version2:"5.8.6001.23551"))){
    report = report_fixed_ver(file_checked:sysPath + "system32\Vbscript.dll", file_version:sysVer, vulnerable_range:"< 5.6.0.8852, 5.7 - 5.7.6002.23291, 5.8 - 5.8.6001.23551");
    security_message(port:0, data:report);
  }
  exit(0);
}

## Windows Vista and Windows Server 2008
## Currently no support for Vista and Windows Server 2008 64 bit
else if(hotfix_check_sp(winVista:3, win2008:3) > 0){
  if(version_is_less(version:sysVer, test_version:"5.7.6002.19005") ||
     version_in_range(version:sysVer, test_version:"5.7.6002.23000", test_version2:"5.7.6002.23291") ||
     (ieVer =~ "^8" && version_in_range(version:sysVer, test_version:"5.8.6001.19000", test_version2:"5.8.6001.19497")) ||
     (ieVer =~ "^8" && version_in_range(version:sysVer, test_version:"5.8.6001.23000", test_version2:"5.8.6001.23551"))){
    report = report_fixed_ver(file_checked:sysPath + "system32\Vbscript.dll", file_version:sysVer, vulnerable_range:"< 5.7.6002.19005, 5.7.6002.23000 - 5.7.6002.23291, 5.8.6001.19000 - 5.8.6001.19497, 5.8.6001.23000 - 5.8.6001.23551");
    security_message(port:0, data:report);
  }
  exit(0);
}

## Windows 7 and Windows 2008 R2
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, win8:1, win8x64:1, win2012:1) > 0){
  if(version_is_less(version:sysVer, test_version:"5.8.7601.18337") ||
     version_in_range(version:sysVer, test_version:"5.8.7601.22000", test_version2:"5.8.7601.22534")){
    report = report_fixed_ver(file_checked:sysPath + "system32\Vbscript.dll", file_version:sysVer, vulnerable_range:"< 5.8.7601.18337, 5.8.7601.22000 - 5.8.7601.22534");
    security_message(port:0, data:report);
    exit(0);
  }

  if(ieVer && ieVer =~ "^10"){
    if(version_is_less(version:sysVer, test_version:"5.8.9200.16775") ||
       version_in_range(version:sysVer, test_version:"5.8.9200.20000", test_version2:"5.8.9200.20900")){
      report = report_fixed_ver(file_checked:sysPath + "system32\Vbscript.dll", file_version:sysVer, vulnerable_range:"< 5.8.9200.16775, 5.8.9200.20000 - 5.8.9200.20900");
      security_message(port:0, data:report);
    }
    exit(0);
  }

  if(ieVer && ieVer =~ "^11"){
    if(version_is_less(version:sysVer, test_version:"5.8.9600.16497")){
      report = report_fixed_ver(file_checked:sysPath + "system32\Vbscript.dll", file_version:sysVer, vulnerable_range:"< 5.8.9600.16497");
      security_message(port:0, data:report);
    }
    exit(0);
  }
}

## Win 8.1
## Currently no support for Windows Server 2012 R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1) > 0){
  if(version_is_less(version:sysVer, test_version:"5.8.9600.16483")){
    report = report_fixed_ver(file_checked:sysPath + "system32\Vbscript.dll", file_version:sysVer, vulnerable_range:"< 5.8.9600.16483");
    security_message(port:0, data:report);
  }
  exit(0);
}

exit(99);