###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_office_ms13-054.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Microsoft Office Remote Code Execution Vulnerability (2848295)
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code as
  the logged-on user.
  Impact Level: System/Application";

tag_affected = "Microsoft Office 2003 Service Pack 3
  Microsoft Office 2007 Service Pack 2
  Microsoft Office 2010 Service Pack 1";
tag_insight = "The flaw is due to an error when processing TrueType fonts and can be
  exploited to cause a buffer overflow via a specially crafted file.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  https://technet.microsoft.com/en-us/security/bulletin/ms13-054";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS13-054.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902980");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-3129");
  script_bugtraq_id(60978);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-07-10 11:19:43 +0530 (Wed, 10 Jul 2013)");
  script_name("Microsoft Office Remote Code Execution Vulnerability (2848295)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/54057/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2817480");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2687309");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2687276");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1028750");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-054");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
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

path = "";
dllVer = "";
offPath = "";

## MS Office 2003/2007/2010
if(!get_kb_item("MS/Office/Ver") =~ "^[11|12|14].*"){
  exit(0);
}


path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
if(path)
{
  foreach ver (make_list("OFFICE12", "OFFICE14"))
  {
    ## Get Version from Ogl.dll
    offPath = path + "\Microsoft Shared\" + ver;
    dllVer = fetch_file_version(sysPath:offPath, file_name:"Ogl.dll");

    if(dllVer &&
       (version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7102.4999") ||
        version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6679.4999")))
    {
      security_message(0);
      exit(0);
    }
  }
}

# Office 2003
path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"ProgramFilesDir");
if(!path){
  exit(0);
}

msPath = path  +  "\Microsoft Office\OFFICE11";
dllVer = fetch_file_version(sysPath:msPath, file_name:"Gdiplus.dll");
if(dllVer)
{
  # Grep for Gdiplus.dll version 11.0 < 11.0.8404
  if(version_in_range(version:dllVer, test_version:"11.0", test_version2:"11.0.8403"))
  {
    security_message(0);
    exit(0);
  }
}
