###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_office_suite_ms15-046.nasl 7582 2017-10-26 11:56:51Z cfischer $
#
# Microsoft Office Suite Remote Code Execution Vulnerability (3057181)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805180");
  script_version("$Revision: 7582 $");
  script_cve_id("CVE-2015-1682", "CVE-2015-1683");
  script_bugtraq_id(74481, 74484);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 13:56:51 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2015-05-13 14:51:10 +0530 (Wed, 13 May 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Suite Remote Code Execution Vulnerability (3057181)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-046.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and check
  appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Flaw exists as user supplied input is
  not properly validated.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  context-dependent attacker to corrupt memory and potentially
  execute arbitrary code.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"
  Microsoft Office 2007 Service Pack 3 and prior
  Microsoft Office 2010 Service Pack 2 and prior
  Microsoft Office 2013 Service Pack 1 and prior.");

  script_tag(name:"solution", value:"Run Windows Update and update the listed
  hotfixes or download and update mentioned hotfixes in the advisory from the
  below link, https://technet.microsoft.com/library/security/MS15-046");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/2965282");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/2965311");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/2999412");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/2965242");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/2975808");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS15-046");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("MS/Office/Ver");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable initialization
exeVer = "";
ortVer = "";
InsPath = "";
comPath = "";
ortconVer = "";

## MS Office 2007
if(get_kb_item("MS/Office/Ver") =~ "^12.*")
{
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
      if(version_in_range(version:exeVer, test_version:"12.0", test_version2:"12.0.6721.4999"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}

## Get Version from mso.dll file version
## For office 2010 Wwlibcxm.dll is mentioned and it is not available so ignoring
## version check for office 2010 https://support.microsoft.com/en-us/kb/2965311

## MS Office 2010
if(get_kb_item("MS/Office/Ver") =~ "^14.*")
{
  ## Get the file version
  comPath = registry_get_sz(key:"SOFTWARE\Microsoft\Office\14.0\Access\InstallRoot",
                            item:"Path");
  if(comPath)
  {
    ## Get the file versions
    ortVer = fetch_file_version(sysPath:comPath, file_name:"Oart.dll");
    ortconVer = fetch_file_version(sysPath:comPath, file_name:"Oartconv.dll");
    if(!isnull(ortVer) || !isnull(ortconVer))
    {
      ## Check the Oart.dll and Oartconv.dll files version
      if(version_in_range(version:ortVer, test_version:"14.0", test_version2:"14.0.7149.4999") ||
         version_in_range(version:ortconVer, test_version:"14.0", test_version2:"14.0.7149.4999"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}


## MS Office 2013
if(get_kb_item("MS/Office/Ver") =~ "^15.*")
{
  ## Get the file version
  comPath = registry_get_sz(key:"SOFTWARE\Microsoft\Office\15.0\Access\InstallRoot",
                            item:"Path");
  if(comPath)
  {
    ## Get the file versions
    ortVer = fetch_file_version(sysPath:comPath, file_name:"Oart.dll");
    if(ortVer)
    {
      ## Check the Oart.dll and Oartconv.dll files version
      if(version_in_range(version:ortVer, test_version:"15.0", test_version2:"15.0.4719.999"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}
