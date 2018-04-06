###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-094.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft Office PowerPoint Remote Code Execution Vulnerabilities (2639142)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a malicious PPT file.
  Impact Level: Application";
tag_affected = "Microsoft PowerPoint 2010
  Microsoft PowerPoint 2007 Service Pack 2
  Microsoft PowerPoint Viewer 2007 Service Pack 2
  Microsoft Office Compatibility Pack for PowerPoint 2007 File Formats SP2";
tag_insight = "The flaws are due to the application loading unspecified libraries in
  an insecure manner. This can be exploited to load an arbitrary library by
  tricking a user into opening a PowerPoint file located on a remote WebDAV
  or SMB share.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms11-094.mspx";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS11-094.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902492");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-3396", "CVE-2011-3413");
  script_bugtraq_id(50967, 50964);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-12-14 08:36:00 +0530 (Wed, 14 Dec 2011)");
  script_name("Microsoft Office PowerPoint Remote Code Execution Vulnerabilities (2639142)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47208");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2596764");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2596843");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2596912");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/MS11-094");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/PowerPnt/Version");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!egrep(pattern:"^(12|14)\..*", string:get_kb_item("MS/Office/Ver"))){
  exit(0);
}

pptVer = get_kb_item("SMB/Office/PowerPnt/Version");
if(pptVer)
{
  if(egrep(pattern:"^(12|14)\..*", string:pptVer))
  {
    ## PowerPoint Check
    ## Check for Powerpnt.exe < 12.0.6600.1000 for PowerPoint 2007
    ## Check for Powerpnt.exe < 14.0.6009.1000 for PowerPoint 2010
    if(version_in_range(version:pptVer, test_version:"12.0", test_version2:"12.0.6600.999") ||
       version_in_range(version:pptVer, test_version:"14.0", test_version2:"14.0.6009.999"))
    {
      security_message(0);
      exit(0);
    }
  }
}

## PowerPoint Viewer Check
ppviewVer = get_kb_item("SMB/Office/PPView/Version");
if(!isnull(ppviewVer))
{
  ## Check for Pptview.exe < 12.0.6654.5000 for PowerPoint Viewer 2007
  if(version_in_range(version:ppviewVer, test_version:"12.0", test_version2:"12.0.6654.4999"))
  {
    security_message(0);
    exit(0);
  }
}

##Microsoft Office Compatibility PowerPoint 2007 File Formats
if(registry_key_exists(key:"SOFTWARE\Microsoft\Office"))
{
  sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                              item:"ProgramFilesDir");
  if(sysPath)
  {
    dllVer = fetch_file_version(sysPath, file_name:"Microsoft Office\Office12\Ppcnv.dll");
    if(dllVer)
    {
      ## Check for Ppcnv.dll 12 < 12.0.6654.5000 PowerPoint 2007 converter
      if(version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6654.4999")){
        security_message(0);
      }
    }
  }
}
