###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-015.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Microsoft Office Visio Viewer Remote Code Execution Vulnerabilities (2663510)
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

tag_impact = "Successful exploitation could allow attackers to gain same user rights as
  the logged on user and execute arbitrary code.
  Impact Level: System/Application";
tag_affected = "Microsoft Visio Viewer 2010 Service Pack 1 and prior.";
tag_insight = "The flaws are due to an unspecified error when validating certain
  data in specially crafted Visio files, this can be exploited to corrupt
  memory.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-015";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS12-015.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902423");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-0019", "CVE-2012-0020", "CVE-2012-0136", "CVE-2012-0137",
                "CVE-2012-0138");
  script_bugtraq_id(51903, 51904, 51906, 51907, 51908);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-02-15 09:34:05 +0530 (Wed, 15 Feb 2012)");
  script_name("Microsoft Office Visio Viewer Remote Code Execution Vulnerabilities (2663510)");
  script_xref(name : "URL" , value : "https://secunia.com/advisories/47946");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/887012");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2597170");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-015");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/VisioViewer/Ver");
  script_require_ports(139, 445);

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

vvVer ="";
visioPath = "";
visiovVer = "";
dllPath = "";

## Get the KB
vvVer = get_kb_item("SMB/Office/VisioViewer/Ver");

## Confirm the visio viewer 2010 installation
if(vvVer && vvVer =~ "^14\..*")
{
  ## Get program files path
  visioPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                              item:"ProgramFilesDir");
  if(visioPath)
  {
    dllPath = visioPath + "\Microsoft Office\Office14\";
    if(dllPath)
    {
      ## Get the version of VVIEWER.dll file
      visiovVer = fetch_file_version(sysPath:dllPath, file_name:"VVIEWER.dll");
      if(visiovVer)
      {
        if(version_in_range(version:visiovVer, test_version:"14.0",
                            test_version2:"14.0.6114.5000")){
          security_message(0);
        }
      }
    }
  }
}
