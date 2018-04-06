###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms07-066.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Vulnerability in Windows Kernel Could Allow Elevation of Privilege (943078)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
# 
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net 
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

tag_impact = "Successful exploitation allows remote attackers to execute arbitrary code
  with kernel privileges.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows Vista.";
tag_insight = "The flaw is due to an unspecified error in the way the Windows Advanced
  Local Procedure Call (ALPC) validates certain conditions of legacy reply paths.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms07-066.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS07-066.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801709");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-01-14 07:39:17 +0100 (Fri, 14 Jan 2011)");
  script_cve_id("CVE-2007-5350");
  script_bugtraq_id(26757);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Vulnerability in Windows Kernel Could Allow Elevation of Privilege (943078)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/28015");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/38729");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2007/Dec/1019075.html");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms07-066.mspx");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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

if(hotfix_check_sp(winVista:3) <= 0){
  exit(0);
}

## Hotfix check
if(hotfix_missing(name:"943078") == 0){
  exit(0);
}

## Get system path for windows vista
dllPath = registry_get_sz(item:"PathName",
                          key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
if(!dllPath){
   exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                    string:dllPath + "\system32\ntoskrnl.exe");

exeVer = GetVer(file:file, share:share);
if(exeVer)
{
  # Windows Vista
  if(hotfix_check_sp(winVista:3) > 0)
  {
    # Grep for ntoskrnl.exe version < 6.0.6000.16575
    if(version_is_less(version:exeVer, test_version:"6.0.6000.16575")){
          security_message(0);
    }
         exit(0);
  }
}
