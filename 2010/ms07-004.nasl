###################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Vector Markup Language Vulnerabilities (929969)
#
# LSS-NVT-2010-042
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2009 LSS <http://www.lss.hr>
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
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

tag_solution = "Run Windows Update or apply patches available on the following web site:
  http://www.microsoft.com/technet/security/Bulletin/MS07-004.mspx";
tag_summary = "Remote exploitation of an integer overflow vulnerability in the 
  Vector Markup Language (VML) support in multiple Microsoft products 
  allows attackers to execute arbitrary code within the context of the user 
  running the vulnerable application.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102053");
  script_version("$Revision: 9745 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-07 13:45:41 +0200 (Mon, 07 May 2018) $");
  script_tag(name:"creation_date", value:"2010-07-08 10:59:30 +0200 (Thu, 08 Jul 2010)");
  script_bugtraq_id(21930);
  script_cve_id("CVE-2007-0024");
  script_name("Microsoft Windows Vector Markup Language Vulnerabilities (929969)");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/122084");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/23677");
  script_xref(name : "URL" , value : "http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=462");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 LSS");
  script_family("Windows : Microsoft Bulletins"); 
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_require_ports(139, 445);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

# MS07-033 Hotfix (929969)
if(hotfix_missing(name:"929969") == 0){
  exit(0);
}

dllPath = registry_get_sz(item:"CommonFilesDir",
                          key:"SOFTWARE\Microsoft\Windows\CurrentVersion");
dllPath += "\Microsoft Shared\VGX\vgx.dll";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

vers = GetVer(file:file, share:share);
if(!vers){
  exit(0);
}

# CVE-2007-0024
if(hotfix_check_sp(win2k:5) > 0)
{
#Vgx.dll 5.0.3848.1800
  SP = get_kb_item("SMB/Win2K/ServicePack");
  if("Service Pack 4" >< SP)
  {
    if(version_in_range(version:vers, test_version:"6.0",
                       test_version2:"6.0.2800.1588")){
     security_message(0); exit(0);
    }
  }

}
else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_in_range(version:vers, test_version:"6.0",
                        test_version2:"6.0.2900.3051") ||
	   version_in_range(version:vers, test_version:"7.0",
                        test_version2:"7.0.6000.16386")){
      security_message(0); exit(0);
    }
  }
  
}
else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if(version_in_range(version:vers, test_version:"6.0",
                        test_version2:"6.0.3790.2851") ||
	   version_in_range(version:vers, test_version:"7.0",
                        test_version2:"7.0.6000.16386")){
      security_message(0); exit(0);
    }
  }
}

