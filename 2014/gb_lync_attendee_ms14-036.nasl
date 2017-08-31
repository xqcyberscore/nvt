###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lync_attendee_ms14-036.nasl 6769 2017-07-20 09:56:33Z teissa $
#
# Microsoft Lync Attendee Remote Code Execution Vulnerabilities (2967487)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804462");
  script_version("$Revision: 6769 $");
  script_cve_id("CVE-2014-1817", "CVE-2014-1818");
  script_bugtraq_id(67897, 67904);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-20 11:56:33 +0200 (Thu, 20 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-06-11 13:51:38 +0530 (Wed, 11 Jun 2014)");
  script_name("Microsoft Lync Attendee Remote Code Execution Vulnerabilities (2967487)");

   tag_summary =
"This host is missing a critical security update according to
Microsoft Bulletin MS14-036.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"The flaws are due to,
- An error within Unicode Scripts Processor.
- An error within GDI+ when validating images.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute arbitrary
code in the context of the currently logged-in user, which may lead to a
complete compromise of an affected computer.

Impact Level: System/Application";

  tag_affected =
"Microsoft Lync Attendee 2010";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms14-036";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2963282");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2963284");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms14-036");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl",
                      "secpod_ms_lync_detect_win.nasl");
  script_mandatory_keys("MS/Lync/Attendee/Ver", "MS/Lync/Attendee/path");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
path = "";
oglVer = "";

## For Microsoft Lync 2010 Attendee (admin level install)
## For Microsoft Lync 2010 Attendee (user level install)
if(get_kb_item("MS/Lync/Attendee/Ver"))
{
  ## Get Installed Path
  path = get_kb_item("MS/Lync/Attendee/path");
  if(path)
  {
    ## Get Version from Ogl.dll
    oglVer = fetch_file_version(sysPath:path, file_name:"Ogl.dll");
    if(oglVer)
    {
      if(version_in_range(version:oglVer, test_version:"4.0", test_version2:"4.0.7577.4445"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}
