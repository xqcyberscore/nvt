###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-022.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft Office PowerPoint Remote Code Execution Vulnerabilities (2489283)
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
  Impact Level: System";
tag_affected = "Microsoft PowerPoint 2010
  Microsoft PowerPoint Viewer 2010
  Microsoft PowerPoint 2002 Service Pack 3
  Microsoft PowerPoint 2003 Service Pack 3
  Microsoft PowerPoint 2007 Service Pack 2
  Microsoft PowerPoint Viewer 2007 Service Pack 2";
tag_insight = "The flaws are caused by errors related to floating point techno-color time bandit,
  persist directory and OfficeArt atoms, which could be exploited by attackers to
  execute arbitrary code by tricking a user into opening a specially crafted
  PowerPoint file.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms11-022.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS11-022.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902411");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-04-13 17:05:53 +0200 (Wed, 13 Apr 2011)");
  script_cve_id("CVE-2011-0655", "CVE-2011-0656", "CVE-2011-0976");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Office PowerPoint Remote Code Execution Vulnerabilities (2489283)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2464617");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2464588");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2464594");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2464623");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2519975");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2519984");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/Bulletin/MS11-022.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
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

if(!egrep(pattern:"^(|10|11|12|14)\..*", string:get_kb_item("MS/Office/Ver"))){
  exit(0);
}

pptVer = get_kb_item("SMB/Office/PowerPnt/Version");
if(pptVer)
{
  if(egrep(pattern:"^(|10|11|12|14)\..*", string:pptVer))
  {
    ## PowerPoint Check
    ## Check for Powerpnt.exe < 10.0.6868.0 for PowerPoint 2002
    ## Check for Powerpnt.exe < 11.0.8334.0 for PowerPoint 2003
    ## Check for Powerpnt.exe < 12.0.6545.5000 for PowerPoint 2007
    if(version_in_range(version:pptVer, test_version:"10.0", test_version2:"10.0.6867.0") ||
       version_in_range(version:pptVer, test_version:"11.0", test_version2:"11.0.8333.0") ||
       version_in_range(version:pptVer, test_version:"12.0", test_version2:"12.0.6545.4999"))
      {
        security_message(0);
        exit(0);
      }
   }
}

# Office Power Point for 2010
if(registry_key_exists(key:"SOFTWARE\Microsoft\Office"))
{
  sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                              item:"ProgramFilesDir");
  if(sysPath)
  {
    dllVer = fetch_file_version(sysPath, file_name:"Microsoft Office\Office14\ppcore.dll");
    if(dllVer)
    {
      ## Check for Ppcore.dll < 14.0.5136.5003 for PowerPoint 2010
      if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.5136.5002"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}

ppviewVer = get_kb_item("SMB/Office/PPView/Version");

## PowerPoint Viewer Check
if (!isnull(ppviewVer))
{
  ## Check for Pptview.exe < 12.0.6550.5000 for PowerPoint Viewer 2007
  ## Check for Pptview.exe < 14.0.5136.5003 for PowerPoint Viewer 2010
  if(version_in_range(version:ppviewVer, test_version:"12.0", test_version2:"12.0.6550.4999") ||
     version_in_range(version:ppviewVer, test_version:"14.0", test_version2:"14.0.5136.5002")){
      security_message(0);
  }
}
