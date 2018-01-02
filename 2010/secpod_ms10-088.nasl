###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-088.nasl 8207 2017-12-21 07:30:12Z teissa $
#
# Microsoft Office PowerPoint Remote Code Execution Vulnerabilities (2293386)
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_affected = "Microsoft PowerPoint 2002 Service Pack 3 and prior
  Microsoft PowerPoint 2003 Service Pack 3 and prior
  Microsoft PowerPoint Viewer 2007 Service Pack 2 and prior";
tag_insight = "The flaw is due to the way that Microsoft PowerPoint parses the
  PPT file format when opening a specially crafted files.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms10-088.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-088.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900261");
  script_version("$Revision: 8207 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 08:30:12 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-11-10 14:58:25 +0100 (Wed, 10 Nov 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-2572", "CVE-2010-2573");
  script_bugtraq_id(44626, 44628);
  script_name("Microsoft Office PowerPoint Remote Code Execution Vulnerabilities (2293386)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2413272");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2413304");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2413381");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms10-088.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver", "MS/Office/Prdts/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

if(egrep(pattern:"^(|10|11|12)\..*", string:get_kb_item("MS/Office/Ver")))
{
  pptVer = get_kb_item("SMB/Office/PowerPnt/Version");
  ppviewVer = get_kb_item("SMB/Office/PPView/Version");

  ## PowerPoint Check
  if(!isnull(pptVer))
  {
    ## Check for Powerpnt.exe < 10.0.6858.0 for PowerPoint 2002
    ## Check for Powerpnt.exe < 11.0.8324.0 for PowerPoint 2003
    if(version_in_range(version:pptVer, test_version:"10.0", test_version2:"10.0.6857") ||
       version_in_range(version:pptVer, test_version:"11.0", test_version2:"11.0.8323")){
      security_message(0);
    }
  }

  ## PowerPoint Viewer Check
  if (!isnull(ppviewVer))
  {
    ## Check for Pptview.exe  < 12.0.6545.5004 for PowerPoint Viewer 2007
    if(version_in_range(version:ppviewVer, test_version:"12.0", test_version2:"12.0.6545.5003")){
      security_message(0);
    }
  }
}
