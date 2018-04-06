###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_directx_code_exec_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Vulnerability in Microsoft DirectShow Could Allow Remote Code Execution
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/MS09-028.mspx

  Workaround: Apply workaround steps mentioned in the reference link.";

tag_impact = "Attacker who successfully exploit this flaw could take complete control of
  an affected system.
  Impact Level: System";
tag_affected = "DirectX 7.0 8.1 and 9.0* on Microsoft Windows 2K
  DirectX 9.0 on Microsoft Windows XP and 2K3";
tag_insight = "Microsoft DirectShow fails to handle supported QuickTime format files. This
  could allow code execution if a user opened a specially crafted QuickTime
  media file when a user is logged on with administrative user rights.";
tag_summary = "This host is installed with Microsoft DirectShow and is prone to
  remote code execution vulnerability.

  This NVT has been replaced by NVT secpod_ms09-028.nasl
  (OID:1.3.6.1.4.1.25623.1.0.900588).";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900097");
  script_version("$Revision: 9350 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-01 09:35:57 +0200 (Mon, 01 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1537");
  script_bugtraq_id(35139);
  script_name("Vulnerability in Microsoft DirectShow Could Allow Remote Code Execution");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/advisory/971778.mspx");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in secpod_ms09-028.nasl.

include("smb_nt.inc");
include("secpod_reg.inc");

# OS with Hotfix Check
if(hotfix_check_sp(win2k:5, xp:4, win2003:3) <= 0){
  exit(0);
}

# Check DirectX is installed
directXver = registry_get_sz(key:"SOFTWARE\Microsoft\DirectX", item:"Version");
if(!directXver){
  exit(0);
}

if(hotfix_check_sp(win2k:5) > 0)
{
  if(directXver =~ "^4\.0[7-9]"){
      security_message(0);
  }
}

else if(hotfix_check_sp(xp:4) > 0)
{
  if(directXver =~ "^4\.09"){
    security_message(0);
  }
}

else if(hotfix_check_sp(win2003:3) > 0)
{
  if(directXver =~ "^4\.09"){
    security_message(0);
  }
}
