###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-040.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# MS Windows Threat Management Gateway Firewall Client Remote Code Execution Vulnerability (2520426)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902444");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-06-15 15:55:00 +0200 (Wed, 15 Jun 2011)");
  script_cve_id("CVE-2011-1889");
  script_bugtraq_id(48181);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("MS Windows Threat Management Gateway Firewall Client Remote Code Execution Vulnerability (2520426)");

  tag_summary =
"This host is missing a critical security update according to
Microsoft Bulletin MS11-040";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"The flaw is due to error when setting proper bounds to the
'NSPLookupServiceNext()' function, that allow remote code execution if an
attacker leveraged a client computer to make specific requests on a system
where the TMG firewall client is used.";

tag_impact = "Successful exploitation could allow remote attackers to execute
arbitrary code in the context of the application. Failed exploit attempts will
result in denial-of-service conditions.

Impact Level: System/Application";

  tag_affected =
"Microsoft Forefront Threat Management Gateway 2010 SP1 and prior.";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms11-040";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2520426");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms11-040");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

key = "";
sysPath = "";
dllVer = "";

key = "SOFTWARE\Microsoft\";

if(!registry_key_exists(key:key)) {
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  sysPath = registry_get_sz(key:key + item, item:"InstallRoot");

  ## confirm the application
  if("Forefront TMG Client" >< sysPath)
  {
    ## Get Version from Fwcmgmt.exe
    dllVer = fetch_file_version(sysPath, file_name:"Fwcmgmt.exe");
    if(!dllVer){
      exit(0);
    }

    if(version_is_less(version:dllVer, test_version:"7.0.7734.182"))
    {
      security_message(0);
      exit(0);
    }
  }
}
