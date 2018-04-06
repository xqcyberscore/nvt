##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-061.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# MS Exchange Server Remote Code Execution Vulnerabilities (2876063)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902992");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-2393", "CVE-2013-3776", "CVE-2013-3781");
  script_bugtraq_id(59129, 61234, 61232);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-08-14 13:28:33 +0530 (Wed, 14 Aug 2013)");
  script_name("MS Exchange Server Remote Code Execution Vulnerabilities (2876063)");

   tag_summary =
"This host is missing a critical security update according to
Microsoft Bulletin MS13-061.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"The flaws exist in the WebReady Document Viewing and Data Loss Prevention
features of Microsoft Exchange Server.";

  tag_impact =
"Successful exploitation could allow an attacker to cause a denial of service
condition or run arbitrary code as LocalService on the affected Exchange
server.

Impact Level: System";

  tag_affected =
"Microsoft Exchange Server 2007 Service Pack 3
Microsoft Exchange Server 2010 Service Pack 2
Microsoft Exchange Server 2010 Service Pack 3";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms13-061";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/54392");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2873746");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2874216");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2866475");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2874216");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-061");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
key = "";
version = "";
exeVer = "";
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
      ## Exchange Server 2007 Service Pack 3 (08.03.0327.001)
      ## Exchange Server 2010 Service Pack 2 (14.02.0375.000)
      ## Exchange Server 2010 Service Pack 3 (14.03.0158.001)
      ## Security Update For Exchange Server 2013 CU2 (KB2874216) (15.00.0712.028)
      ## Security Update For Exchange Server 2013 CU1 (KB2874216) (15.00.0620.034)
      if(version_is_less(version:exeVer, test_version:"8.3.327.1") ||
         version_in_range(version:exeVer, test_version:"14.2", test_version2:"14.2.374") ||
         version_in_range(version:exeVer, test_version:"14.3", test_version2:"14.3.158") ||
         version_in_range(version:exeVer, test_version:"15.0.600", test_version2:"15.0.620.33") ||
         version_in_range(version:exeVer, test_version:"15.0.700", test_version2:"15.0.712.27"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}
