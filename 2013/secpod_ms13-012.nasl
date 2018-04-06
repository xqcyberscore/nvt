##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-012.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# MS Exchange Server Remote Code Execution Vulnerabilities (2809279)
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

tag_impact = "Successful exploitation could allow an attacker to cause a denial of service
  condition or run arbitrary code as LocalService on the affected Exchange
  server.
  Impact Level: System/Application";

tag_affected = "Microsoft Exchange Server 2007 Service Pack 3
  Microsoft Exchange Server 2010 Service Pack 2";
tag_insight = "Flaws are in Microsoft Exchange Server WebReady Document Viewing and will
  allow remote code execution in the security context of the transcoding service
  on the Exchange server if a user previews a specially crafted file using
  Outlook Web App (OWA)";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms13-012";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS13-012.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902948");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-0393", "CVE-2013-0418");
  script_bugtraq_id(57364, 57357);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-02-13 10:16:56 +0530 (Wed, 13 Feb 2013)");
  script_name("MS Exchange Server Remote Code Execution Vulnerabilities (2809279)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52133/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2809279");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms13-012");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
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


## Variables Initialization
key = "";
version = "";
exeVer = "";
exchangePath = "";


## Confirm the application
if(!registry_key_exists(key:"SOFTWARE\Microsoft\Exchange")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

foreach version (make_list("Microsoft Exchange v14", "Microsoft Exchange"))
{
  key = key + version;
  exchangePath = registry_get_sz(key:key, item:"InstallLocation");

  if(exchangePath)
  {
    ## Get Version from ExSetup.exe file version
    exeVer = fetch_file_version(sysPath:exchangePath,
             file_name:"Bin\ExSetup.exe");

    if(exeVer)
    {
      ## Check for ExSetup.exe version
      if(version_is_less(version:exeVer, test_version:"8.3.298.3") ||
         version_in_range(version:exeVer, test_version:"14.2", test_version2:"14.2.342.2"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}
