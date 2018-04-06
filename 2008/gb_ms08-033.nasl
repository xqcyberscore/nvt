###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms08-033.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# Vulnerabilities in DirectX Could Allow Remote Code Execution (951698)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Updated by Madhuri D <dmadhuri@secpod.com> on 2010-12-09
#  - To detect the 'quartz.dll' file version on Windows vista and 2008 server
#
# Copyright:
# Copyright (c) 2008 Intevation GmbH, http://www.intevation.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation allows remote attackers to execute arbitrary code when
  a user opens a specially crafted media file. An attacker could take complete
  control of an affected system.
  Impact Level: System";
tag_summary = "This host has DirectX installed, which is prone to remote code
  execution vulnerabilities.";

tag_affected = "DirectX 7.0, 8.1, 9.0, 9.0a, 9.0b and 9.0c on Microsoft Windows 2000
  DirectX 9.0, 9.0a, 9.0b and 9.0c on Microsoft Windows XP and 2003
  DirectX 10.0 on Microsoft Windows Vista and 2008 Server";
tag_insight = "The flaws are due to
  - error in the Windows MJPEG Codec when performing error checking on MJPEG
    video streams embedded in ASF or AVI media files which can be exploited
    with a specially crafted MJPEG file.
  - error in the parsing of Class Name variables in Synchronized Accessible
    Media Interchange (SAMI) files which can be exploited with a specially
    crafted SAMI file.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and update
  mentioned hotfixes in the advisory from the below link.
  http://www.microsoft.com/technet/security/bulletin/ms08-033.mspx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800104");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-09-30 14:16:17 +0200 (Tue, 30 Sep 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-0011","CVE-2008-1444");
  script_bugtraq_id(29581, 29578);
  script_xref(name:"CB-A", value:"08-0097");
  script_name("Vulnerabilities in DirectX Could Allow Remote Code Execution (951698)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/30579");
  script_xref(name : "URL" , value : "http://www.frsirt.com/english/advisories/2008/1780");
  script_xref(name : "URL" , value : "http://www.us-cert.gov/cas/techalerts/TA08-162B.html");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-08-040/");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms08-033.mspx");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2008 Intevation GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

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

# Check the hotfix applicability to each OS
if(hotfix_check_sp(win2k:5, xp:4, win2003:3, win2008:2, winVista:2) <= 0){
  exit(0);
}

dllFile = smb_get_system32root();
if(!dllFile){
  exit(0);
}

dllFile += "\quartz.dll";

# Check DirectX is installed
directXver = registry_get_sz(key:"SOFTWARE\Microsoft\DirectX", item:"Version");
if(!egrep(pattern:"^4\.0[7-9]\..*", string:directXver)){
  exit(0);
}

# MS08-033 Hotfix check
if(hotfix_missing(name:"951698") == 0){
  exit(0);
}

if(hotfix_check_sp(win2k:5) > 0)
{
  if(egrep(pattern:"^4\.07", string:directXver))
  {
    fileVer = get_version(dllPath:dllFile, string:"prod", offs:600000);
    if(fileVer == NULL){
      exit(0);
    }

    # Grep Quartz.dll version < 6.1.9.734
    if(egrep(pattern:"^6\.01\.09\.0?([0-6]?[0-9]?[0-9]|7([0-2][0-9]|3[0-3]))$",
             string:fileVer)){
      security_message(0);
    }
  }
  else if(egrep(pattern:"^4\.08", string:directXver))
  {
    # Grep Quartz.dll version < 6.3.1.891
    if(egrep(pattern:"^6\.03\.01\.0?([0-7]?[0-9]?[0-9]|8([0-8][0-9]|90))$",
             string:fileVer)){
      security_message(0);
    }
  }
  else if(egrep(pattern:"^4\.09", string:directXver))
  {
    # Grep Quartz.dll version < 6.5.1.909
    if(egrep(pattern:"^6\.05\.0?1\.0?([0-8]?[0-9]?[0-9]|90[0-8])$",
             string:fileVer)){
      security_message(0);
    }
    # Grep Quartz.dll version < 6.5.2600.1316
    else if(egrep(pattern:"^6\.05\.2600\.(0?[0-9]?[0-9]?[0-9]|1([0-2][0-9]" +
                       "[0-9]|3(0[0-9]|1[0-5])))$", string:fileVer)){
      security_message(0);
    }
  }
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  if(egrep(pattern:"^4\.09", string:directXver))
  {
    fileVer = get_version(dllPath:dllFile, string:"prod", offs:600000);;
    if(fileVer == NULL){
      exit(0);
    }

    SP = get_kb_item("SMB/WinXP/ServicePack");
    if("Service Pack 2" >< SP)
    {
      # Grep Quartz.dll version < 6.5.2600.3367
      if(egrep(pattern:"^6\.05\.2600\.([0-2]?[0-9]?[0-9]?[0-9]|3([0-2][0-9]" +
                       "[0-9]|3([0-5][0-9]|6[0-6])))$", string:fileVer)){
        security_message(0);
      }
    }
    else if("Service Pack 3" >< SP)
    {
      # Grep Quartz.dll version < 6.5.2600.5596
      if(egrep(pattern:"^6\.05\.2600\.([0-4]?[0-9]?[0-9]?[0-9]|5([0-4][0-9]" +
                       "[0-9]|5([0-8][0-9]|9[0-5])))$", string:fileVer)){
        security_message(0);
      }
    }
  }
  exit(0);
}

if(hotfix_check_sp(win2003:3) > 0)
{
  if(egrep(pattern:"^4\.09", string:directXver))
  {
    fileVer = get_version(dllPath:dllFile, string:"prod", offs:600000);
    if(fileVer == NULL){
      exit(0);
    }

    SP = get_kb_item("SMB/Win2003/ServicePack");
    if("Service Pack 1" >< SP)
    {
      # Grep Quartz.dll version < 6.5.3790.3130
      if(egrep(pattern:"^6\.05\.3790\.([0-2]?[0-9]?[0-9]?[0-9]|3(0[0-9]" +
                       "[0-9]|1[0-2][0-9]))$", string:fileVer)){
        security_message(0);
      }
    }
    else if("Service Pack 2" >< SP)
    {
      # Grep Quartz.dll version < 6.5.3790.4283
      if(egrep(pattern:"^6\.05\.3790\.([0-3]?[0-9]?[0-9]?[0-9]|4([01][0-9]" +
                       "[0-9]|2([0-7][0-9]|8[0-2])))$", string:fileVer)){
        security_message(0);
      }
    }
  }
}

## Get the 'Quartz.dll' path for Windows Vista and 2008 Server
dllPath = smb_get_system32root();
if(!dllPath){
  exit(0);
}

fileVer =  fetch_file_version(sysPath:dllPath, file_name:"\Quartz.dll");
if(fileVer)
{
  # Windows Vista
  if(hotfix_check_sp(winVista:2) > 0)
  {
    SP = get_kb_item("SMB/WinVista/ServicePack");
    if("Service Pack 1" >< SP)
    {
      # Grep for Quartz.dll version  < 6.6.6001.18063
      if(version_is_less(version:fileVer, test_version:"6.6.6001.18063")){
          security_message(0);
      }
      exit(0);
    }
  }

  # Windows Server 2008
  else if(hotfix_check_sp(win2008:2) > 0)
  {
    SP = get_kb_item("SMB/Win2008/ServicePack");
    if("Service Pack 1" >< SP)
    {
      # Grep for Quartz.dll version  < 6.6.6001.18063
      if(version_is_less(version:fileVer, test_version:"6.6.6001.18063")){
          security_message(0);
      }
      exit(0);
    }
  }
}
