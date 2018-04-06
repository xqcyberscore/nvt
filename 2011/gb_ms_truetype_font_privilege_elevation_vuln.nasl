###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_truetype_font_privilege_elevation_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft Windows TrueType Font Parsing Privilege Elevation Vulnerability
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code with
  kernel-level privileges. Failed exploit attempts may result in a
  denial-of-service condition.
  Impact Level: System";
tag_affected = "Microsoft Windows 7 Service Pack 1 and prior
  Microsoft Windows XP Service Pack 3 and prior
  Microsoft Windows Vista Service Pack 2 and prior
  Microsoft Windows Server 2008 Service Pack 2 and prior
  Microsoft Windows server 2003 Service Pack 2 and prior";
tag_insight = "The flaw is due to due to an error within the Win32k kernel-mode
  driver when parsing TrueType fonts.";
tag_solution = "Apply the workaround from below link,
  http://support.microsoft.com/kb/2639658";
tag_summary = "The host is installed with Microsoft Windows operating system and is prone to
  pivilege escalation vulnerability.

  This NVT has been replaced by NVT secpod_ms11-087.nasl
  (OID:1.3.6.1.4.1.25623.1.0.902767).";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802500");
  script_version("$Revision: 9351 $");
  script_tag(name:"deprecated", value:TRUE);
  script_cve_id("CVE-2011-3402");
  script_bugtraq_id(50462);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-11-07 16:44:35 +0530 (Mon, 07 Nov 2011)");
  script_name("Microsoft Windows TrueType Font Parsing Privilege Elevation Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46724/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2639658");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/advisory/2639658");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Windows");
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

exit(66); ## This NVT is deprecated as addressed in secpod_ms11-087.nasl

include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_smb_func.inc");

 exit(0);  ## plugin may results to FP

## Check for OS
if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllPath = sysPath + "\system32\t2embed.dll";

## Exit if file does not exist
if(!dllPath){
 exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

## Check if file is accessible by checking its size
dllSize = get_file_size(file:file, share:share);
if(dllSize != NULL){
  security_message(0);
}
