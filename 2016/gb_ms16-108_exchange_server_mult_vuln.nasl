###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms16-108_exchange_server_mult_vuln.nasl 5836 2017-04-03 09:37:08Z teissa $
#
# Microsoft Exchange Server Multiple Vulnerabilities (3185883)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
CPE = "cpe:/a:microsoft:exchange_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809313");
  script_version("$Revision: 5836 $");
  script_cve_id("CVE-2016-0138", "CVE-2016-3378", "CVE-2016-3379");
  script_bugtraq_id(92833, 92806, 92836);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-03 11:37:08 +0200 (Mon, 03 Apr 2017) $");
  script_tag(name:"creation_date", value:"2016-09-14 10:21:52 +0530 (Wed, 14 Sep 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Exchange Server Multiple Vulnerabilities (3185883)");

  script_tag(name: "summary" , value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-108.");

  script_tag(name: "vuldetect" , value:"Get the vulnerable file version and check
  appropriate patch is applied or not.");

  script_tag(name: "insight" , value:"Multiple flaws exist due to
  - The way that Microsoft Exchange Server parses email messages.
  - An open redirect vulnerability exists in Microsoft Exchange that
    could lead to Spoofing.
  - The way that Microsoft Outlook handles meeting invitation requests.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  an attacker to discover confidential user information that is contained in
  Microsoft Outlook applications, also attacker could trick the user and potentially
  acquire sensitive information, such as the user's credentials.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"
  Microsoft Exchange Server 2013 Service Pack 1
  Microsoft Exchange Server 2013 Cumulative Update 12
  Microsoft Exchange Server 2013 Cumulative Update 13
  Microsoft Exchange Server 2016 Cumulative Update 1
  Microsoft Exchange Server 2016 Cumulative Update 2");

  script_tag(name: "solution" , value:"Run Windows Update and update the listed
  hotfixes or download and update mentioned hotfixes in the advisory from the
  https://technet.microsoft.com/library/security/MS16-108");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3184736");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS16-108");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_exchange_server_detect.nasl");
  script_mandatory_keys("MS/Exchange/Server/Ver");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initialization
ExVer = "";
dllVer = "";
path = "";

## Get the installed path
exchangePath = get_app_location(cpe:CPE);
if(!exchangePath || "Could not find the install location" >< exchangePath){
  exit(0);
}

cum_update = get_kb_item("MS/Exchange/Cumulative/Update/no");

## Get Version from ExSetup.exe file version
exeVer = fetch_file_version(sysPath:exchangePath, file_name:"Bin\ExSetup.exe");
if(exeVer)
{
  ## Exchange Server 2013
  if(version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.847.49"))
  {
    Vulnerable_range = "15.0 - 15.0.847.50";
    VULN = TRUE ;
  }

  ## Exchange Server 2013 CU 13
  else if(exeVer =~ "^(15.0)" && "Cumulative Update 13" >< cum_update)
  {
    if(version_is_less(version:exeVer, test_version:"15.0.1210.6"))
    {
      Vulnerable_range = "Less than 15.0.1210.6";
      VULN = TRUE ;
    }
  }

  ## Exchange Server 2013 CU 12
  else if(exeVer =~ "^(15.0)" && "Cumulative Update 12" >< cum_update)
  {
    if(version_is_less(version:exeVer, test_version:"15.0.1178.9"))
    {
      Vulnerable_range = "Less than 15.0.1178.9";
      VULN = TRUE ;
    }
  }

  ##Exchange Server 2016 CU 1
  else if(exeVer =~ "^(15.1)" && "Cumulative Update 1" >< cum_update)
  {
    if(version_is_less(version:exeVer, test_version:"15.1.396.37"))
    {
      Vulnerable_range = "Less than 15.1.396.37";
      VULN = TRUE ;
    }
  }
 
  ##Exchange Server 2016 CU 2
  else if(exeVer =~ "^(15.1)" && "Cumulative Update 2" >< cum_update)
  {
    if(version_is_less(version:exeVer, test_version:"15.1.466.37"))
    {
      Vulnerable_range = "Less than 15.1.466.37";
      VULN = TRUE ;
    }
  }

}

if(VULN)
{
  report = 'File checked:     ' + exchangePath + "\Bin\ExSetup.exe" + '\n' +
           'File version:     ' + exeVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
