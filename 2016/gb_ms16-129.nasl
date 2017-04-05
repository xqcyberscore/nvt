###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms16-129.nasl 5612 2017-03-20 10:00:41Z teissa $
#
# Microsoft Edge Multiple Vulnerabities (3199057)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809091");
  script_version("$Revision: 5612 $");
  script_cve_id("CVE-2016-7195", "CVE-2016-7196", "CVE-2016-7198", "CVE-2016-7199",
                "CVE-2016-7200", "CVE-2016-7201", "CVE-2016-7202", "CVE-2016-7203",
                "CVE-2016-7204", "CVE-2016-7208", "CVE-2016-7209", "CVE-2016-7227",
                "CVE-2016-7239", "CVE-2016-7240", "CVE-2016-7241", "CVE-2016-7242",
                "CVE-2016-7243");
  script_bugtraq_id(92828, 92834, 92789, 92830, 92829, 92832, 92807, 92793);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-03-20 11:00:41 +0100 (Mon, 20 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-11-09 08:52:24 +0530 (Wed, 09 Nov 2016)");
  script_name("Microsoft Edge Multiple Vulnerabities (3199057)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-129");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The multiple flaws exists due to,
  - The Microsoft Edge improperly handles objects in memory.
  - The Microsoft Edge IMproperly parse HTTP content.
  - The Microsoft browser XSS filter is abused to leak sensitive page information."); 

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to execute arbitrary code in the context of the current user, redirect 
  a user to a specially crafted website, detect specific files on the user's 
  computer, trick a user into allowing access to the user's My Documents folder, 
  obtain sensitive information from certain web pages in the affected browser.

  Impact Level: System");

  script_tag(name:"affected", value:"
  Microsoft Windows 10 x32/x64.
  Microsoft Windows 10 Version 1511 x32/x64.
  Microsoft Windows 10 Version 1607 x32/x64");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://technet.microsoft.com/library/security/MS16-129");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3199057");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/library/security/ms16-129");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
edgePath = "";
edgeVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

## Get System Path
edgePath = smb_get_systemroot();
if(!edgePath){
  exit(0);
}

## Get the Edgehtml.dll version
if(!edgeVer = fetch_file_version(sysPath: edgePath, file_name:"system32\Edgehtml.dll")){;
  exit(0);
}

## Windows 10
if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  ## Check for Edgehtml.dll version
  if(version_is_less(version:edgeVer, test_version:"11.0.10240.17184"))
  {
    Vulnerable_range = "Less than 11.0.10240.17184";
    VULN = TRUE ;
  }

  ## Windows 10 Version 1511
  else if(version_in_range(version:edgeVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.671"))
  {
    Vulnerable_range = "11.0.10586.0 - 11.0.10586.671";
    VULN = TRUE ;
  }

  ## Windows 10 version 1607
  else if(version_in_range(version:edgeVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.446"))
  {
    Vulnerable_range = "11.0.14393.0 - 11.0.14393.446";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + edgePath + "\system32\Edgehtml.dll"+ '\n' +
           'File version:     ' + edgeVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;   
  security_message(data:report);
  exit(0);
}
