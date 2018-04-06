###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms08-004.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft Windows TCP/IP Denial of Service Vulnerability (946456)
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

tag_impact = "Successful exploitation leads to stop and automatically restart a vulnerable
  system via a specially crafted packet.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows Vista.";
tag_insight = "The flaw is due to an unspecified error in the 'TCP/IP' processing of
  packets received from DHCP (Dynamic Host Configuration Protocol) servers.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms08-004.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS08-004.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801705");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-01-13 17:08:42 +0100 (Thu, 13 Jan 2011)");
  script_cve_id("CVE-2008-0084");
  script_bugtraq_id(27634);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Microsoft Windows TCP/IP Denial of Service Vulnerability (946456)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/28828");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2008/Feb/1019383.html");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms08-004.mspx");

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
if(hotfix_missing(name:"946456") == 0){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                      item:"PathName");
if(!sysPath){
  exit(0);
}

sysVer = fetch_file_version(sysPath, file_name:"system32\drivers\tcpip.sys");
if(!sysVer){
  exit(0);
}

## Windows Vista
if(hotfix_check_sp(winVista:3) > 0)
{
  ## Grep for tcpip.sys version < 6.0.6000.16627
  if(version_is_less(version:sysVer, test_version:"6.0.6000.16627")){
      security_message(0);
  }
  exit(0);
}
