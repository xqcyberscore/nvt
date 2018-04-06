###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-089.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft Office Remote Code Execution Vulnerability (2590602)
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code as
  the logged-on user.
  Impact Level: System/Application";
tag_affected = "Microsoft Office 2007 Service Pack 3 and prior.
  Microsoft Office 2010 Service Pack 1 and prior.";
tag_insight = "The flaw is due to a use-after-free error when parsing Word documents
  and can be exploited to dereference already freed memory.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/MS11-089";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS11-089.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902495");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-1983");
  script_bugtraq_id(50956);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-12-14 11:40:47 +0530 (Wed, 14 Dec 2011)");
  script_name("Microsoft Office Remote Code Execution Vulnerability (2590602)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47098");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2596785");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2589320");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/MS11-089");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
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

## MS Office 2007, 2010
if(get_kb_item("MS/Office/Ver") =~ "^[12|14].*")
{
  ## Get Office File Path
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
  if(!path) {
    exit(0);
  }

  foreach ver (make_list("OFFICE12", "OFFICE14"))
  {
    ## Get Version from msptls.dll
    offPath = path + "\Microsoft Shared\" + ver;
    dllVer = fetch_file_version(sysPath:offPath, file_name:"msptls.dll");
    if(dllVer)
    {
      ## Grep for msptls.dll versions
      if(version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6654.4999")||
         version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.6112.4999"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}
