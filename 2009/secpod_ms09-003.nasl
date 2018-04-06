###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-003.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Vulnerabilities in Microsoft Exchange Could Allow Remote Code Execution (959239)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation allows remote arbitrary code execution sending
  a specially crafted MAPI command using the EMSMDB32 provider.

  Impact Level: System";
tag_affected = "Microsoft Exchange Server 2000/2003/2007 on Windows Servers";
tag_insight = "- Error exists within the decoding of Transport Neutral Encapsulation
    Format (TNEF) data that causes memory corruption when a user opens or
    previews a specially crafted e-mail message sent in TNEF format.

  - Error exists within the processing of MAPI commands in the EMSMDB2.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,

  http://www.microsoft.com/technet/security/bulletin/ms09-003.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-003.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900079");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-02-11 16:51:00 +0100 (Wed, 11 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0098", "CVE-2009-0099");
  script_bugtraq_id(33134, 33136);
  script_name("Vulnerabilities in Microsoft Exchange Could Allow Remote Code Execution (959239)");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms09-003.mspx");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, win2003:3) <= 0){
  exit(0);
}

appName = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\Uninstall\Microsoft Exchange",
                          item:"DisplayName");
if(!appName){
  exit(0);
}

function Get_FileVersion()
{
  excFile = registry_get_sz(key:"SOFTWARE\Microsoft\Exchange\Setup",
                            item:"MsiInstallPath");
  if(!excFile){
    exit(0);
  }

  dllVer = fetch_file_version( sysPath:excFile, file_name:"\bin\Davex.dll" );
  if(!dllVer){
    return 0;
  }
  else return dllVer;
}


if("Microsoft Exchange Server 2003" >< appName)
{
  if(hotfix_missing(name:"959897") == 0){
    exit(0);
  }

  fileVer = Get_FileVersion();
  if(!fileVer){
    exit(0);
  }

  # Check for version < 6.5.7654.12
  if(version_is_less(version:fileVer, test_version:"6.5.7654.12")){
    security_message(0);
  }
}

else if("Microsoft Exchange Server 2007" >< appName)
{
  if(hotfix_missing(name:"959241") == 0){
    exit(0);
  }

  fileVer = Get_FileVersion();
  if(!fileVer){
    exit(0);
  }

  #  Check for version < 8.01.0336.0000
  if(version_is_less(version:fileVer, test_version:"8.01.0336.0000")){
    security_message(0);
  }
}
