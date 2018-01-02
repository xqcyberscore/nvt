###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-084.nasl 8246 2017-12-26 07:29:20Z teissa $
#
# Windows Local Procedure Call Privilege Elevation Vulnerability (2360937)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright (c) 2010 SecPod, http://www.secpod.org
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code
  with NetworkService privileges.
  Impact Level: System";
tag_affected = "Microsoft Windows 2003 Service Pack 2.
  Microsoft Windows XP Service Pack 3 and prior.";
tag_insight = "The flaw is due to a stack overflow error in the Remote Procedure Call
  Subsystem (RPCSS) when exchanging port messages between LPC and the LRPC
  Server (RPC EndPoint Mapper).";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/MS10-084.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-084.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902322");
  script_version("$Revision: 8246 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-26 08:29:20 +0100 (Tue, 26 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-10-13 17:10:12 +0200 (Wed, 13 Oct 2010)");
  script_cve_id("CVE-2010-3222");
  script_bugtraq_id(43777);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Windows Local Procedure Call Privilege Elevation Vulnerability (2360937)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2360937");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2631");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/MS10-084.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
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
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3) <= 0){
  exit(0);
}

# Check Hotfix Missing 2360937
if(hotfix_missing(name:"2360937") == 0){
  exit(0);
}
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(!sysPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:sysPath + "\Rpcrt4.dll");

sysVer = GetVer(file:file, share:share);
if(!sysVer){
  exit(0);
}

# Grep for Rpcrt4.dll < 5.2.3790.4759
if(version_is_less(version:sysVer, test_version:"5.2.3790.4759")){
  security_message(0);
}
