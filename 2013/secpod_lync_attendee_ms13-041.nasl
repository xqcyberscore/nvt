###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_lync_attendee_ms13-041.nasl 6074 2017-05-05 09:03:14Z teissa $
#
# Microsoft Lync Attendee Remote Code Execution Vulnerability (2834695)
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

tag_impact = "Successful exploitation could allow an attacker could execute arbitrary
  code in the context of the current user by sharing specially crafted
  content, such as a file or a program, as a presentation in a Lync or
  Communicator session and then convince a user to view or share the
  specially crafted content.
  Impact Level: System/Application";

tag_affected = "Microsoft Lync Attendee 2010";
tag_insight = "A use-after-free error within the Lync control can be exploited to
  dereference already freed memory.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms13-041";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS13-041.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902972";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6074 $");
  script_bugtraq_id(59791);
  script_cve_id("CVE-2013-1302");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-05-05 11:03:14 +0200 (Fri, 05 May 2017) $");
  script_tag(name:"creation_date", value:"2013-05-15 18:20:36 +0530 (Wed, 15 May 2013)");
  script_name("Microsoft Lync Attendee Remote Code Execution Vulnerability (2834695)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2827752");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2827751");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53363/");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-041");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl",
                      "secpod_ms_lync_detect_win.nasl");
  script_mandatory_keys("MS/Lync/Attendee/Ver", "MS/Lync/Attendee/path");
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
    oglVer = fetch_file_version(sysPath:path, file_name:"Appshapi.dll");
    if(oglVer)
    {
      if(version_in_range(version:oglVer, test_version:"4.0", test_version2:"4.0.7577.4377"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}

