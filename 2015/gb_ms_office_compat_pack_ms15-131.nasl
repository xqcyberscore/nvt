###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_office_compat_pack_ms15-131.nasl 7582 2017-10-26 11:56:51Z cfischer $
#
# Microsoft Office Compatibility Pack Remote Code Execution Vulnerabilities (3116111)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.806177");
  script_version("$Revision: 7582 $");
  script_cve_id("CVE-2015-6040", "CVE-2015-6122", "CVE-2015-6124", "CVE-2015-6172");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 13:56:51 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2015-12-09 14:32:12 +0530 (Wed, 09 Dec 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Compatibility Pack Remote Code Execution Vulnerabilities (3116111)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-113.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and check
  appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,
  - Microsoft Excel improperly handles the loading of dynamic link library
    (DLL) files.
  - Improper handling of files in the memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code and corrupt memory in the context of the
  current user.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"
  Microsoft Office Compatibility Pack Service Pack 3 and prior.");

  script_tag(name:"solution", value:"Run Windows Update and update the listed
  hotfixes or download and update mentioned hotfixes in the advisory from the
  below link, https://technet.microsoft.com/en-us/security/bulletin/ms15-131");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3116111");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3114431");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3114457");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/library/security/MS15-131");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/ComptPack/Version", "SMB/Office/XLCnv/Version", "SMB/Office/WordCnv/Version");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initialization
xlcnvVer = "";
wordcnvVer = "";
path = "";
sysVer = "";

## Check for Office Compatibility Pack 2007
if(get_kb_item("SMB/Office/ComptPack/Version") =~ "^12\..*")
{
  xlcnvVer = get_kb_item("SMB/Office/XLCnv/Version");
  if(xlcnvVer)
  {
    ## Check for Office Version 2007 with compatibility pack version 12.0 < 12.0.6739.5000
    ## took the file excelconv.exe which is updated after patch
    if(version_in_range(version:xlcnvVer, test_version:"12.0", test_version2:"12.0.6739.4999"))
    {
      report = 'File checked:     excelconv.exe' + '\n' +
               'File version:     ' + xlcnvVer  + '\n' +
               'Vulnerable range:  12.0 - 12.0.6739.4999' + '\n' ;
      security_message(data:report);
      exit(0);
    }
  }
}

## Check for Office Version 2007 with compatibility pack
wordcnvVer = get_kb_item("SMB/Office/WordCnv/Version");
if(wordcnvVer && wordcnvVer =~ "^12.*")
{
  # Office Word Converter
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                              item:"ProgramFilesDir");
  if(path)
  {
    sysVer = fetch_file_version(sysPath:path + "\Microsoft Office\Office12", file_name:"Wordcnv.dll");
    if(sysVer)
    {
      ## Check for Office Version 2007 with compatibility pack version 12.0 < 12.0.6740.5000 
      if(version_in_range(version:sysVer, test_version:"12.0", test_version2:"12.0.6740.4999"))
      {
        report = 'File checked:   Wordcnv.dll' + '\n' +
               'File version:     ' + sysVer  + '\n' +
               'Vulnerable range:  12.0 - 12.0.6740.4999' + '\n' ;
       security_message(data:report);
       exit(0);
      }
    }

    ## Get Office File Path
    InsPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                       item:"CommonFilesDir");
    if(InsPath)
    {
      ## Get Version from Mso.dll
      offPath = InsPath + "\Microsoft Shared\Office12";
      exeVer = fetch_file_version(sysPath:offPath, file_name:"Mso.dll");
      if(exeVer)
      {
        ## Check for mso.dll version
        if(version_in_range(version:exeVer, test_version:"12.0", test_version2:"12.0.6739.4999"))
        {
          report = 'File checked:     Mso.dll' + '\n' +
                   'File version:     ' + exeVer  + '\n' +
                   'Vulnerable range:  12.0 - 12.0.6739.4999' + '\n' ;
          security_message(data:report);
          exit(0);
        }
      }
    }
  }
}
