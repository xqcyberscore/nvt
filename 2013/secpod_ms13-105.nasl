##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-105.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# MS Exchange Server Remote Code Execution Vulnerabilities (2915705)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903418");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-1330", "CVE-2013-5072", "CVE-2013-5763", "CVE-2013-5791");
  script_bugtraq_id(62221, 64085, 63741, 63076);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-12-11 10:09:38 +0530 (Wed, 11 Dec 2013)");
  script_name("MS Exchange Server Remote Code Execution Vulnerabilities (2915705)");

   tag_summary =
"This host is missing a critical security update according to Microsoft
Bulletin MS13-105.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Multiple flaws are due to,
- An unspecified error in the Outlook Web Access (OWA) service account.
- Certain unspecified input is not properly sanitised before being returned
  to the user.";

  tag_impact =
"Successful exploitation will allow an attacker to run arbitrary code and
execute arbitrary HTML and script code in a user's browser session in context
of an affected site.

Impact Level: System";

  tag_affected =
"Microsoft Exchange Server 2013
Microsoft Exchange Server 2007 Service Pack 3
Microsoft Exchange Server 2010 Service Pack 2
Microsoft Exchange Server 2010 Service Pack 3";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms13-105";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/55998");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1029329");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2903911");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2903903");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2905616");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2880833");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1029459");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-105");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
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

## Variables Initialization
key = "";
exeVer = "";
version = "";
exchangePath = "";

## Confirm the application
if(!registry_key_exists(key:"SOFTWARE\Microsoft\Exchange") &&
   !registry_key_exists(key:"SOFTWARE\Microsoft\ExchangeServer")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
foreach version (make_list("Microsoft Exchange v14", "Microsoft Exchange", "Microsoft Exchange v15"))
{
  exchangePath = registry_get_sz(key: key + version, item:"InstallLocation");

  if(exchangePath)
  {
    ## Get Version from ExSetup.exe file version
    exeVer = fetch_file_version(sysPath:exchangePath,
             file_name:"Bin\ExSetup.exe");

    if(exeVer)
    {
      ## Exchange Server 2007 Service Pack 3 (08.03.0342.004)
      ## Exchange Server 2010 Service Pack 2 (14.02.0390.003)
      ## Exchange Server 2010 Service Pack 3 (14.03.174.001)
      ## Security Update For Exchange Server 2013 CU2 (15.00.0712.031)
      ## Security Update For Exchange Server 2013 CU3 (15.00.0775.041)
      if(version_is_less(version:exeVer, test_version:"8.3.342.4") ||
         version_in_range(version:exeVer, test_version:"14.2", test_version2:"14.2.390.2") ||
         version_in_range(version:exeVer, test_version:"14.3", test_version2:"14.3.174") ||
         version_in_range(version:exeVer, test_version:"15.0.770", test_version2:"15.0.775.40") ||
         version_in_range(version:exeVer, test_version:"15.0.710", test_version2:"15.0.712.30"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}
