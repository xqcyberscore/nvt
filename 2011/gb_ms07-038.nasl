###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms07-038.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft Windows Vista Teredo Interface Firewall Bypass Vulnerability
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

tag_impact = "Successful exploitation allows remote attacker to bypass firewall settings
  and possibly obtain sensitive information about the system.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows Vista.";
tag_insight = "The flaw is due to an error in the handling of the Teredo transport
  mechanism resulting in network traffic being handled incorrectly though the
  Teredo interface. This may result in certain firewall rules being bypassed.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms07-038.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS07-038.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801717");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-01-14 09:03:25 +0100 (Fri, 14 Jan 2011)");
  script_cve_id("CVE-2007-3038");
  script_bugtraq_id(24779);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_name("Microsoft Windows Vista Teredo Interface Firewall Bypass Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/26001");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2007/Jul/1018354.html");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms07-038.mspx");

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
if(hotfix_missing(name:"935807") == 0){
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
                    string:dllPath + "\system32\drivers\tunnel.sys");

dllVer = GetVer(file:file, share:share);
if(dllVer)
{
  # Windows Vista
  if(hotfix_check_sp(winVista:3) > 0)
  {
    # Grep for tunnel.sys version < 6.0.6000.16501
    if(version_is_less(version:dllVer, test_version:"6.0.6000.16501")){
          security_message(0);
    }
         exit(0);
  }
}
