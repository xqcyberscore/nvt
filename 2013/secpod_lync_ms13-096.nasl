###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_lync_ms13-096.nasl 6115 2017-05-12 09:03:25Z teissa $
#
# Microsoft Lync Remote Code Execution Vulnerability (2908005)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 SecPod, http://www.secpod.com
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.903421";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6115 $");
  script_cve_id("CVE-2013-3906");
  script_bugtraq_id(63530);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-05-12 11:03:25 +0200 (Fri, 12 May 2017) $");
  script_tag(name:"creation_date", value:"2013-12-11 13:17:21 +0530 (Wed, 11 Dec 2013)");
  script_name("Microsoft Lync Remote Code Execution Vulnerability (2908005)");

   tag_summary =
"This host is missing a critical security update according to
Microsoft Bulletin MS13-096.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"The flaw is due to an error when handling TIFF files within the Microsoft
Graphics Component (GDI+) and can be exploited to cause a memory corruption.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute arbitrary
code in the context of the currently logged-in user, which may lead to a
complete compromise of an affected computer.

Impact Level: System/Application";

  tag_affected =
"Microsoft Lync 2010
Microsoft Lync 2013";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms13-096";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);

  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2899397");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2850057");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-096");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl",
                      "secpod_ms_lync_detect_win.nasl");
  script_mandatory_keys("MS/Lync/Ver", "MS/Lync/path");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
path = "";
commVer = "";

## Check for Microsoft Lync 2010/2013
if(get_kb_item("MS/Lync/Ver"))
{
  ## Get Installed Path
  path = get_kb_item("MS/Lync/path");
  if(path)
  {
    ## Get Version from Rtmpltfm.dll
    commVer = fetch_file_version(sysPath:path, file_name:"Rtmpltfm.dll");
    if(commVer)
    {
      if(version_in_range(version:commVer, test_version:"5.0", test_version2:"5.0.8308.382") ||
         version_in_range(version:commVer, test_version:"4.0", test_version2:"4.0.7577.4414"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}
