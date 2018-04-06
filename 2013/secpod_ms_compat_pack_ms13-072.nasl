###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_compat_pack_ms13-072.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# MS Office Compatibility Pack Remote Code Execution Vulnerabilities (2845537)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903404");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-3160", "CVE-2013-3847", "CVE-2013-3848", "CVE-2013-3849",
                "CVE-2013-3850", "CVE-2013-3851", "CVE-2013-3852", "CVE-2013-3853",
                "CVE-2013-3854", "CVE-2013-3855", "CVE-2013-3856", "CVE-2013-3857",
                "CVE-2013-3858");
  script_bugtraq_id(62162, 62165, 62168, 62169, 62170, 62171, 62216, 62217, 62220,
                    62222, 62223, 62224, 62226);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-09-11 17:22:16 +0530 (Wed, 11 Sep 2013)");
  script_name("MS Office Compatibility Pack Remote Code Execution Vulnerabilities (2845537)");

  tag_summary =
"This host is missing an important security update according to
Microsoft Bulletin MS13-072.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Multiple flaws are due to error exists when processing XML data and some
unspecified errors.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute the arbitrary
code, cause memory corruption and compromise the system.

Impact Level: System/Application ";

  tag_affected =
"Compatibility Pack for Microsoft Office 2007 file formats";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms13-072";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/54737");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2760823");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms13-072");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/WordCnv/Version");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initailization
wordcnvVer = "";
path = "";
sysVer = "";

# Check for Office Word Version 2007 with compatibility pack
wordcnvVer = get_kb_item("SMB/Office/WordCnv/Version");
if(wordcnvVer && wordcnvVer =~ "^12.*")
{
  # Office Word Converter
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                              item:"ProgramFilesDir");
  if(path)
  {
    sysVer = fetch_file_version(sysPath:path + "\Microsoft Office\Office12", file_name:"Wordcnv.dll");

    if(sysVer)
    {
      # Check for Word Converter 2007 version 12.0 < 12.0.6683.5001
      if(version_in_range(version:sysVer, test_version:"12.0", test_version2:"12.0.6683.5000"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}
