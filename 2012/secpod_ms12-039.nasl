###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-039.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Microsoft Lync Remote Code Execution Vulnerabilities (2707956)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow an attacker to execute arbitrary code
  with kernel-level privileges. Failed exploit attempts may result in a
  denial of service condition.
  Impact Level: System/Application";
tag_affected = "Microsoft Lync 2010
  Microsoft Lync 2010 Attendee
  Microsoft Lync 2010 Attendant
  Microsoft Communicator 2007 R2";
tag_insight = "- An error within the Win32k kernel-mode driver (win32k.sys) when parsing
    TrueType fonts.
  - An error in the t2embed.dll module when parsing TrueType fonts.
  - The client loads libraries in an insecure manner, which can be exploited
    to load arbitrary libraries by tricking a user into opening a '.ocsmeet'
    file located on a remote WebDAV or SMB share.
  - An unspecified error in the 'SafeHTML' API when sanitising HTML code can
    be exploited to execute arbitrary HTML and script code in the user's chat
    session.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-039";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS12-039.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902842");
  script_version("$Revision: 9352 $");
  script_bugtraq_id(50462, 53335, 53831, 53833);
  script_cve_id("CVE-2011-3402", "CVE-2012-0159", "CVE-2012-1849", "CVE-2012-1858");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-06-13 11:11:11 +0530 (Wed, 13 Jun 2012)");
  script_name("Microsoft Lync Remote Code Execution Vulnerabilities (2707956)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48429");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1027150");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-039");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_lync_detect_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Lync/Installed");

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

## Variables Initialization
path = "";
oglVer = "";
attVer = "";
commVer = "";

## Check for Microsoft Lync 2010/Communicator 2007 R2
if(get_kb_item("MS/Lync/Ver"))
{
  ## Get Installed Path
  path = get_kb_item("MS/Lync/path");
  if(path)
  {
    ## Get Version from communicator.exe
    commVer = fetch_file_version(sysPath:path, file_name:"communicator.exe");
    if(commVer)
    {
      if(version_in_range(version:commVer, test_version:"3.5", test_version2:"3.5.6907.252")||
         version_in_range(version:commVer, test_version:"4.0", test_version2:"4.0.7577.4097"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}

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
      if(version_in_range(version:oglVer, test_version:"4.0", test_version2:"4.0.7577.4097"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}

## Check for Microsoft Lync 2010 Attendant
if(get_kb_item("MS/Lync/Attendant/Ver"))
{
  ## Get Installed Path
  path = get_kb_item("MS/Lync/Attendant/path");
  if(path)
  {
    ## Get Version from AttendantConsole.exe
    attVer = fetch_file_version(sysPath:path, file_name:"AttendantConsole.exe");
    if(attVer)
    {
      if(version_in_range(version:attVer, test_version:"4.0", test_version2:"4.0.7577.4097"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}
