###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_dns_devolution_resolving_weakness.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Microsoft Windows DNS Devolution Third-Level Domain Name Resolving Weakness (971888)
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

tag_impact = "Successful attacks may result in disclosure of the private IP address and
  authentication credentials, modification of client proxy settings, phishing,
  redirection to other malicious sites, enticing vulnerable users to download
  malware.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows 2k  Service Pack 4 and prior
  Microsoft Windows XP  Service Pack 3 and prior
  Microsoft Windows 2k3 Service Pack 2 and prior";
tag_insight = "The flaw is due to design error in the DNS devolution process which can
  be exploited by setting up a malicious site and carry out attacks against
  victims who are inadvertently directed to the malicious site.";
tag_solution = "Apply the Security update from below link,
  http://www.microsoft.com/technet/security/advisory/971888.mspx";
tag_summary = "This host has Microsoft DNS Devolution and is prone to Third-Level
  Domain Name Resolving Weakness.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900873");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-09-29 09:16:03 +0200 (Tue, 29 Sep 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_bugtraq_id(35255);
  script_name("Microsoft Windows DNS Devolution Third-Level Domain Name Resolving Weakness (971888)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/957579");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/advisory/971888.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows");
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

if(hotfix_check_sp(xp:4, win2k:5, win2003:3) <= 0){
  exit(0);
}

# MS Secruity Updated check
if(hotfix_missing(name:"957579") == 0){
  exit(0);
}

dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(!dllPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                    string:dllPath + "\dnsapi.dll");

dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

# Windows 2K
if(hotfix_check_sp(win2k:5) > 0)
{
  # Grep for dnsapi.dll version < 5.0.2195.7280
  if(version_is_less(version:dllVer, test_version:"5.0.2195.7280")){
    security_message(0);
  }
}
# Windows XP
else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    # Grep for dnsapi.dll < 5.1.2600.3557
    if(version_is_less(version:dllVer, test_version:"5.1.2600.3557")){
      security_message(0);
    }
  }
  else if("Service Pack 3" >< SP)
  {
    # Grep for dnsapi.dll < 5.1.2600.5797
    if(version_is_less(version:dllVer, test_version:"5.1.2600.5797")){
      security_message(0);
    }
  }
  else
    security_message(0);
}
# Windows 2003
else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    # Grep for dnsapi.dll version < 5.2.3790.4498
    if(version_is_less(version:dllVer, test_version:"5.2.3790.4498")){
      security_message(0);
    }
  }
  else
    security_message(0);
}
