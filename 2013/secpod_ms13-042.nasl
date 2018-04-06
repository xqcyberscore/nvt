###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-042.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Microsoft Office Publisher Remote Code Execution Vulnerability (2830397)
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a specially crafted publisher files.
  Impact Level: System/Application";

tag_affected = "Microsoft Publisher 2003 Service Pack 3 and prior
  Microsoft Publisher 2007 Service Pack 3 and prior
  Microsoft Publisher 2010 Service Pack 1 and prior";
tag_insight = "Multiple flaws are due to,
  - An unspecified errors when handling array size, return values,
    table range data,  NULL values.
  - An integer overflow vulnerability exists.
  - A signedness error exists when parsing certain data, which can be
    exploited to corrupt memory.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms13-042";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS13-042.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902970");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-1316", "CVE-2013-1317", "CVE-2013-1318", "CVE-2013-1319",
                "CVE-2013-1320", "CVE-2013-1321", "CVE-2013-1322", "CVE-2013-1323",
                "CVE-2013-1327", "CVE-2013-1328", "CVE-2013-1329");
  script_bugtraq_id(59761, 59762, 59764, 59766, 59763, 59767, 59768, 59769, 59770,
                    59771, 59772);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-05-15 10:32:57 +0530 (Wed, 15 May 2013)");
  script_name("Microsoft Office Publisher Remote Code Execution Vulnerability (2830397)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53370/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2810047");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2597971");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2553147");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-042");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl",
                      "gb_smb_windows_detect.nasl");
  script_mandatory_keys("SMB/Office/Publisher/Version");
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

## Variable Initialization
pubVer = "";

## Grep for Office Publisher Version from KB
pubVer = get_kb_item("SMB/Office/Publisher/Version");
if(pubVer && pubVer =~ "^(11|12|14)\..*")
{
  ## Grep for Mspub.exe version 11 < 11.0.8402, 12 <  12.0.6676.5000 14 < 14.0.6137.5000
  if(version_in_range(version:pubVer, test_version:"11.0",test_version2:"11.0.8401") ||
     version_in_range(version:pubVer, test_version:"12.0",test_version2:"12.0.6676.4999")||
     version_in_range(version:pubVer, test_version:"14.0",test_version2:"14.0.6137.4999"))
  {
    security_message(0);
    exit(0);
  }
}
