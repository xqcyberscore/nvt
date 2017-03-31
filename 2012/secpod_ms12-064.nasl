###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-064.nasl 5366 2017-02-20 13:55:38Z cfi $
#
# Microsoft Office Word Remote Code Execution Vulnerabilities (2742319)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_insight = "-  An error when parsing the PAPX section can be exploited to corrupt memory
     via a specially crafted Word file.

     NOTE: This vulnerability affects Microsoft Word 2007 only.

  - A use-after-free error exists when handling listid and can be exploited
    via a specially crafted RTF file.";

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a specially crafted word and RTF files.
  Impact Level: System/Application";
tag_affected = "Microsoft Word Viewer
  Microsoft Office 2003 Service Pack 3
  Microsoft Office 2007 Service Pack 2
  Microsoft Office 2007 Service Pack 3
  Microsoft Office 2010 Service Pack 1
  Microsoft Office Web Apps 2010 Service Pack 1
  Microsoft SharePoint Server 2010 Service Pack 1
  Microsoft Office Compatibility Pack Service Pack 2
  Microsoft Office Compatibility Pack Service Pack 3";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-064";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS12-064.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902926";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5366 $");
  script_cve_id("CVE-2012-0182", "CVE-2012-2528");
  script_bugtraq_id(55780, 55781);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 14:55:38 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2012-10-10 08:46:36 +0530 (Wed, 10 Oct 2012)");
  script_name("Microsoft Office Word Remote Code Execution Vulnerabilities (2742319)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50835/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2598237");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2687401");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2687315");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2687314");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2553488");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2687485");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2687483");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-064");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl",
                      "secpod_ms_office_detection_900025.nasl",
                      "gb_ms_office_web_apps_detect.nasl",
                      "gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_require_keys("SMB/Office/Word/Version", "SMB/Office/WordView/Version",
                      "SMB/Office/WordCnv/Version", "MS/Office/Web/Apps/Path");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initailization
winwordVer = "";
wordcnvVer = "";
path = "";
sysVer = "";
wordviewVer = "";
version = "";
dllVer = "";

# Microsoft Office Word 2003/2007/2010
winwordVer = get_kb_item("SMB/Office/Word/Version");
if(winwordVer)
{
  # Grep for version Winword.exe 12 < 12.0.6662.5003, 11< 11.0.8348
  if(version_in_range(version:winwordVer, test_version:"11.0", test_version2:"11.0.8347") ||
     version_in_range(version:winwordVer, test_version:"12.0", test_version2:"12.0.6662.5002") ||
     version_in_range(version:winwordVer, test_version:"14.0", test_version2:"14.0.6123.5004"))
  {
    security_message(0);
    exit(0);
  }
}

# Check for Office Word Version 2007 with compatibility pack
wordcnvVer = get_kb_item("SMB/Office/WordCnv/Version");
if(wordcnvVer)
{
  # Office Word Converter
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                             item:"ProgramFilesDir");
  if(path)
  {
    path = "\Microsoft Office\Office12";
    sysVer = fetch_file_version(sysPath:path, file_name:"Wordcnv.dll");
    if(sysVer)
    {
      # Check for Word Converter 2007 version 12.0 < 12.0.6662.5003
      if(version_in_range(version:sysVer, test_version:"12.0", test_version2:"12.0.6662.5002"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}

# Check for Word Viewer 11.0 < 11.0.8348
wordviewVer = get_kb_item("SMB/Office/WordView/Version");
if(wordviewVer)
{
  if(version_in_range(version:wordviewVer, test_version:"11.0", test_version2:"11.0.8347"))
  {
    security_message(0);
    exit(0);
  }
}

## SharePoint Server 2010
CPE = "cpe:/a:microsoft:sharepoint_server";
if(version = get_app_version(cpe:CPE, nvt:SCRIPT_OID))
{
  ## SharePoint Server 2010 (wosrv)
  if(version =~ "^14\..*")
  {
    key = "SOFTWARE\Microsoft\Office Server\14.0";
    file = "Msoserver.Dll";   ## File is not mentioned in bulletin
                              ## Based on the after applying patch it is taken.
  }

  if(key && registry_key_exists(key:key) && file)
  {
    if(path = registry_get_sz(key:key, item:"BinPath"))
    {
      dllVer = fetch_file_version(sysPath:path, file_name:file);
      if(dllVer)
      {
        if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.6123.5000"))
        {
          security_message(0);
          exit(0);
        }
      }
    }
  }
}

## Microsoft Office Web Apps 2010 sp1
CPE = "cpe:/a:microsoft:office_web_apps";
if(version = get_app_version(cpe:CPE, nvt:SCRIPT_OID))
{
  ##  ## Microsoft Office Web Apps 2010 sp1
  if(version =~ "^14\..*")
  {
    path = get_kb_item("MS/Office/Web/Apps/Path");
    if(path && "Could not find the install" >!< path )
    {

      path = path + "\14.0\WebServices\ConversionService\Bin\Converter";
      dllVer = fetch_file_version(sysPath:path, file_name:"msoserver.dll");
      if(dllVer)
      {
        if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.6123.5000"))
        {
          security_message(0);
          exit(0);
        }
      }
    }
  }
}
