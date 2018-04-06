###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-044.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Microsoft Visio Information Disclosure Vulnerability (2834692)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attackers to disclose potentially
  sensitive information.
  Impact Level: Application";

tag_affected = "Microsoft Visio 2007 Service Pack 3 and prior
  Microsoft Visio 2003 Service Pack 3 and prior
  Microsoft Visio 2010 Service Pack 1 and prior";
tag_insight = "The flaw is due to an error in the application when parsing XML files with
  external entities. This can be exploited to disclose the contents of
  arbitrary files.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms13-044";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS13-044.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902967");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-1301");
  script_bugtraq_id(59765);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-03-13 13:32:19 +0530 (Wed, 13 Mar 2013)");
  script_name("Microsoft Visio Information Disclosure Vulnerability (2834692)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53380");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2810062");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2596595");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2810068");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-044");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

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
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initialization
sysPath = "";
exeVer = "";

## Check for Office Visio
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                             "\App Paths\visio.exe", item:"Path");
if(!sysPath){
  exit(0);
}

visVer = fetch_file_version(sysPath, file_name:"Visbrgr.dll");
if(visVer && visVer =~ "^11\..*")
{
  if(version_in_range(version:visVer, test_version:"11.0", test_version2:"11.0.8401.0000"))
  {
    security_message(0);
    exit(0);
  }
}

## Get file version
exeVer = fetch_file_version(sysPath, file_name:"visio.exe");
if(exeVer && exeVer =~ "^(12|14)\..*")
{
  # Check for visio.exe version for 2003 2007 and 2010
  if(version_in_range(version:exeVer, test_version:"12.0", test_version2:"12.0.6676.4999") ||
     version_in_range(version:exeVer, test_version:"14.0", test_version2:"14.0.7100.4999"))
  {
    security_message(0);
    exit(0);
  }
}
