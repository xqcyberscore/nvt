###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_winword_ms13-043.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Microsoft Office Word Remote Code Execution Vulnerability (2830399)
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
  tricking a user into opening a specially crafted word and RTF files.
  Impact Level: System/Application";

tag_affected = "Microsoft Word 2003 Service Pack 3 and prior";
tag_insight = "The flaw is due to an error when parsing Rich Text Format (RTF) data related
  to the listoverridecount and can be exploited to corrupt memory.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms13-043";
tag_summary = "This host is missing a important security update according to
  Microsoft Bulletin MS13-043.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902968");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-1335");
  script_bugtraq_id(59759);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-05-15 09:30:40 +0530 (Wed, 15 May 2013)");
  script_name("Microsoft Office Word Remote Code Execution Vulnerability (2830399)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53379");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2810046");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-043");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl",
                      "gb_smb_windows_detect.nasl");
  script_mandatory_keys("SMB/Office/Word/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initailization
winwordVer = "";

# Microsoft Office Word 2003
winwordVer = get_kb_item("SMB/Office/Word/Version");
if(winwordVer)
{
  # Grep for version Winword.exe 11 < 11.0.8402
  if(version_in_range(version:winwordVer, test_version:"11.0", test_version2:"11.0.8401"))
  {
    security_message(0);
    exit(0);
  }
}
