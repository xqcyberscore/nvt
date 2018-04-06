###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_windows_fscpe_bof_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft Windows Fax Cover Page Editor BOF Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will allow the attacker to cause a heap-based buffer
  overflow via a Fax Cover Page file containing specially crafted content.

  Impact Level: System/Application";
tag_affected = "Fax Services Cover Page Editor 5.2 r2 on,

  Microsoft Windows XP Service Pack 3 and prior.

  Microsoft Windows 2K3 Service Pack 2 and prior.

  Microsoft Windows 7";
tag_insight = "The flaw is due to an input validation error and a use-after-free
  error in the Fax Cover Page Editor 'fxscover.exe' when a function
  'CDrawPoly::Serialize()' reads in data from a Fax Cover Page file ('.cov').";
tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Fax Cover Page Editor and is prone to
  buffer overflow vulnerabilities.

 This NVT has been replaced by NVT secpod_ms11-024.nasl
(OID:1.3.6.1.4.1.25623.1.0.902408).";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801580");
  script_version("$Revision: 9351 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-01-27 07:47:27 +0100 (Thu, 27 Jan 2011)");
  script_cve_id("CVE-2010-4701");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows Fax Cover Page Editor BOF Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42747");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1024925");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15839/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16024/");

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
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in secpod_ms11-024.nasl

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, win2003:3, win7:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllPath = sysPath + "\system32\fxscover.exe";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

## Get Version from fxscover.exe file
dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

## Check for fxscover.exe version
if(version_is_less_equal(version:dllVer, test_version:"5.2.3790.3959")){
  security_message(0);
}
