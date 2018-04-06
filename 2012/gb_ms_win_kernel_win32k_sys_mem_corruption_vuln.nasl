###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_win_kernel_win32k_sys_mem_corruption_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Microsoft Windows Kernel 'win32k.sys' Memory Corruption Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary
code on the system with kernel-level privileges.

Impact Level: System";

tag_affected = "Microsoft Windows 7 Professional 64-bit";

tag_insight = "The flaw is due to an error in win32k.sys, when handling a
specially crafted web page containing an IFRAME with an overly large 'height'
attribute viewed using the Apple Safari browser.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "Microsoft Windows 7 Professional 64-bit is prone to memory
corruption vulnerability.

This NVT has been replaced by NVT secpod_ms12-008.nasl
(OID:1.3.6.1.4.1.25623.1.0.902810).";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802379");
  script_tag(name:"creation_date", value:"2012-01-13 16:00:36 +0100 (Fri, 13 Jan 2012)");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_version("$Revision: 9352 $");
  script_tag(name:"deprecated", value:TRUE);
  script_cve_id("CVE-2011-5046");
  script_bugtraq_id(51122);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows Kernel 'win32k.sys' Memory Corruption Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47237");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71873");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18275/");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in secpod_ms12-008.nasl

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win7:2) <= 0){
  exit(0);
}

#Get the system architecture
key = "SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
if(!registry_key_exists(key:key)){
  exit(0);
}

#Check if its 64-bit system
sysArch = registry_get_sz(key:key, item:"PROCESSOR_ARCHITECTURE");
if("AMD64" >< sysArch)
{
  ## Get System Path
  sysPath = smb_get_systemroot();
  if(!sysPath ){
    exit(0);
  }

  ## Get Version from Win32k.sys
  sysVer = fetch_file_version(sysPath, file_name:"system32\Win32k.sys");

  if(!isnull(sysVer))
  {
    if(version_is_less_equal(version:sysVer, test_version:"6.1.7601.17730"))
    {
      security_message(0);
      exit(0);
    }
  }
}
