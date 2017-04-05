###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_windows_sp_mult_vuln.nasl 5659 2017-03-21 11:24:51Z cfi $
#
# Microsoft Windows Service Pack Missing Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902909");
  script_version("$Revision: 5659 $");
  script_cve_id("CVE-1999-0662");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-03-21 12:24:51 +0100 (Tue, 21 Mar 2017) $");
  script_tag(name:"creation_date", value:"2012-03-27 12:06:13 +0530 (Tue, 27 Mar 2012)");
  script_name("Microsoft Windows Service Pack Missing Multiple Vulnerabilities");

  script_tag(name: "summary" , value:"This host is installed Microsoft Windows
  and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value: "Get the installed service pack version
  and check whether it is vulnerable or not.");

  script_tag(name: "insight" , value: "The flaws are due to a system critical
  service pack not installed or is outdated or obsolete.");

  script_tag(name: "impact" , value: "Successful exploitation will allow remote
  attackers to compromise a vulnerable system.

  Impact Level: System");

  script_tag(name: "affected" , value: "Microsoft Windows 7,
  Microsoft Windows 2K SP3 and prior,
  Microsoft Windows XP SP2 and prior,
  Microsoft Windows 2K3 SP1 and prior,
  Microsoft Windows Vista SP1 and prior,
  Microsoft Windows Server 2008 SP1 and prior.");

  script_tag(name: "solution" , value: "Apply the latest Service Pack,
  For Updates refer, http://www.microsoft.com");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/1233");
  script_xref(name : "URL" , value : "http://www.cvedetails.com/cve/CVE-1999-0662/");

  script_summary("Check for the Microsoft Windows Service Pack version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_keys("SMB/Win2008/ServicePack", "SMB/Win7/ServicePack", "SMB/Win2K/ServicePack",
                      "SMB/WinXP/ServicePack", "SMB/Win2003/ServicePack", "SMB/WinVista/ServicePack");
  exit(0);
}


include("version_func.inc");

## Variables Initialization
spVer = "" ;
ver = "";
SP = "";

## Get the service pack version
function check_sp(SP)
{
  if("Service Pack" >< SP)
  {
    spVer = eregmatch(pattern:"Service Pack ([0-9.]+)", string:SP);
    if(spVer[1]){
       return spVer[1];
    }
    else return 0;
  }
}

## Check service pack version for Windows XP
SP = get_kb_item("SMB/WinXP/ServicePack");
if(SP && (ver = check_sp(SP)))
{
  if(version_is_less(version:ver, test_version:"3"))
  {
    security_message(0);
    exit(0);
  }
}

## Check service pack version for Windows server 2003
SP = get_kb_item("SMB/Win2003/ServicePack");
if(SP && (ver = check_sp(SP)))
{
  if(version_is_less(version:ver, test_version:"2"))
  {
    security_message(0);
    exit(0);
  }
}


## Check service pack version for Windows Vista
SP = get_kb_item("SMB/WinVista/ServicePack");
if(SP && (ver = check_sp(SP)))
{
  if(version_is_less(version:ver, test_version:"2"))
  {
    security_message(0);
    exit(0);
  }
}

## Check service pack version for Windows Server 2008
SP = get_kb_item("SMB/Win2008/ServicePack");
if(SP && (ver = check_sp(SP)))
{
  if(version_is_less(version:ver, test_version:"2"))
  {
    security_message(0);
    exit(0);
  }
}

## Check service pack version for Windows 7
SP = get_kb_item("SMB/Win7/ServicePack");
if(SP && (ver = check_sp(SP)))
{
  if(version_is_less(version:ver, test_version:"1"))
  {
    security_message(0);
    exit(0);
  }
}

## Check service pack version for Windows 2000
SP = get_kb_item("SMB/Win2K/ServicePack");
if(SP && (ver = check_sp(SP)))
{
  if(version_is_less(version:ver, test_version:"4"))
  {
    security_message(0);
    exit(0);
  }
}
