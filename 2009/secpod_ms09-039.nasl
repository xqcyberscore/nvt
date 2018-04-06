###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-039.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Microsoft Windows WINS Remote Code Execution Vulnerability (969883)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
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

tag_impact = "Successful exploitation will let the attacker execute arbitrary code with
  elevated privileges, may result in server crash.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows 2k  Service Pack 4 and prior
  Microsoft Windows 2k3 Service Pack 2 and prior";
tag_insight = "- An Heap overflow error exists when processing specially crafted WINS network
    packets, which could be exploited to crash an affected server.
  - WINS server improperly validates and does not restrict buffer lengths
    passed to the heap, which could be exploited to crash an affected
    server.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link.
  http://www.microsoft.com/technet/security/bulletin/ms09-039.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-039.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900814");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-08-13 19:09:22 +0200 (Thu, 13 Aug 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1923", "CVE-2009-1924");
  script_bugtraq_id(35980, 35981);
  script_name("Microsoft Windows WINS Remote Code Execution Vulnerability (969883)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36213/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/969883");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2234");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/MS09-039.mspx");

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
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

# MS09-039 Hotfix check
if(hotfix_missing(name:"969883") == 0){
  exit(0);
}

if(!registry_key_exists(key:"SYSTEM\CurrentControlSet\Services\WINS")){
  exit(0);
}

exePath = registry_get_sz(item:"Install Path",
                          key:"SOFTWARE\Microsoft\COM3\Setup");
if(!exePath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                    string:exePath + "\wins.exe");
fileVer = GetVer(file:file, share:share);
if(!fileVer){
  exit(0);
}

# Win 2000 Server
if(hotfix_check_sp(win2k:5) > 0)
{
  # Grep for wins.exe version < 5.0.2195.7300
  if(version_is_less(version:fileVer, test_version:"5.0.2195.7300")){
    security_message(0);
  }
}
# Win 2003 Server
else if(hotfix_check_sp(win2003:3) > 0)
{
  # Grep for wins.exe version < 5.2.3790.4520
  if(version_is_less(version:fileVer, test_version:"5.2.3790.4520")){
    security_message(0);
  }
}
