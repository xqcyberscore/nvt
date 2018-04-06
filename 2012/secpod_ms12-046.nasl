###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-046.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Visual Basic for Applications Remote Code Execution Vulnerability (2707960)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code affected system.
  Impact Level: System/Application";
tag_affected = "Microsoft Visual Basic for Applications
  Microsoft Office 2003 Service Pack 3 and prior
  Microsoft Office 2007 Service Pack 3 and prior
  Microsoft Office 2010 Service Pack 1 and prior";
tag_insight = "Microsoft Visual Basic for Applications incorrectly restricts the path used
  for loading external libraries, which can be exploited by tricking a user to
  open a legitimate Microsoft Office related file located in the same network
  directory as a specially crafted dynamic link library (DLL) file.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-046";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS12-046.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903034");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-1854");
  script_bugtraq_id(54303);
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-07-11 12:07:45 +0530 (Wed, 11 Jul 2012)");
  script_name("Visual Basic for Applications Remote Code Execution Vulnerability (2707960)");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl",
                      "smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49800/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/976321");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2598243");
  script_xref(name : "URL" , value : "http://support.microsoft.com/KB/2598361");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2553447");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2688865");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/KB2598361");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-046");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initialization
officeVer = "";
dllPath = "";
dllVer6 = "";
dllVer7 = "";
accVer = "";

## Get CommonFilesDir path
dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
              item:"CommonFilesDir");
if(!dllPath){
  exit(0);
}

### Confirm the office 2003, 2007 and 2010 installation.
officeVer = get_kb_item("MS/Office/Ver");

## Grep VBE6.DLL file version.
dllVer6 = fetch_file_version(sysPath:dllPath,
              file_name:"Microsoft Shared\VBA\VBA6\VBE6.DLL");

if(dllVer6)
{
  ## Check for VBE6.DLL version
  if(version_is_less(version:dllVer6, test_version:"6.5.10.54"))
  {
    security_message(0);
    exit(0);
  }
}

if(officeVer =~ "^14\..*")
{
  ## Grep VBE7.DLL file version.
  dllVer7 = fetch_file_version(sysPath:dllPath,
           file_name:"Microsoft Shared\VBA\VBA7\VBE7.DLL");

  if(dllVer7)
  {
    ## Check for VBE7.DLL version
    if(version_in_range(version:dllVer7, test_version:"7.0", test_version2:"7.0.16.26"))
    {
      security_message(0);
      exit(0);
    }
  }

  ## Grep for ACEES.DLL file version
  accVer = fetch_file_version(sysPath:dllPath,
             file_name:"Microsoft Shared\OFFICE14\ACEES.DLL");

  if(accVer)
  {
    ## Check for ACEES.DLL file version
    if(version_in_range(version:accVer, test_version:"14.0", test_version2:"14.0.6015.999")){
      security_message(0);
    }
  }
}
