###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-023.nasl 8274 2018-01-03 07:28:17Z teissa $
#
# Microsoft Office Publisher Remote Code Execution Vulnerability (981160)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation could execute arbitrary code on the remote system
  via a specially crafted Publisher file.
  Impact Level: Application";
tag_affected = "Microsoft Office Publisher 2002 SP 3 and prior
  Microsoft Office Publisher 2003 SP 3 and prior
  Microsoft Office Publisher 2007 SP 2 and prior.";
tag_insight = "The flaw is due to error in opening a specially crafted 'Publisher' file. This
  can be exploited to corrupt memory and cause an invalid value to be dereferenced
  as a pointer.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link.
  http://www.microsoft.com/technet/security/bulletin/ms10-023.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-023.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902158");
  script_version("$Revision: 8274 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-03 08:28:17 +0100 (Wed, 03 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-04-14 17:51:53 +0200 (Wed, 14 Apr 2010)");
  script_cve_id("CVE-2010-0479");
  script_bugtraq_id(39347);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Office Publisher Remote Code Execution Vulnerability (981160)");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms09-23.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/Publisher/Version");
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

## Check for Office XP or 2003 or 2007
officeVer = get_kb_item("MS/Office/Ver");
if(!officeVer){
  exit(0);
}

if(officeVer =~ "^[10|11|12].*")
{
  ## Grep for Office Publisher Version from KB
  pubVer = get_kb_item("SMB/Office/Publisher/Version");
  if(!pubVer){
    exit(0);
  }

  ## Check for Office Publisher 10.0 < 10.0.6861.0
  ## Check for Office Publisher 11.0 < 11.0.8321.0
  ## Check for Office Publisher 12.0 < 12.0.6527.5000
  if(version_in_range(version:pubVer, test_version:"10.0",test_version2:"10.0.6860") ||
     version_in_range(version:pubVer, test_version:"11.0",test_version2:"11.0.8320") ||
     version_in_range(version:pubVer, test_version:"12.0",test_version2:"12.0.6527.4999")){
    security_message(0);
  }
}
