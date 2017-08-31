##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms14-008.nasl 6759 2017-07-19 09:56:33Z teissa $
#
# Microsoft Forefront Protection For Exchange RCE Vulnerability (2927022)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:microsoft:microsoft_forefront_protection";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.903430";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6759 $");
  script_cve_id("CVE-2014-0294");
  script_bugtraq_id(65397);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-19 11:56:33 +0200 (Wed, 19 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-02-12 10:41:31 +0530 (Wed, 12 Feb 2014)");
  script_name("Microsoft Forefront Protection For Exchange RCE Vulnerability (2927022)");

   tag_summary =
"This host is missing a critical security update according to Microsoft
Bulletin MS14-008.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"The flaw is due to an unspecified error when parsing mail content.";

  tag_impact =
"Successful exploitation will allow an attacker to run arbitrary code via a
specially crafted email message and compromise a vulnerable system.

Impact Level: System/Application";

  tag_affected =
"Microsoft Forefront Protection 2010 for Exchange Server";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms14-008";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/56788");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2927022");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms14-008");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "gb_ms_forefront_protection_detect.nasl");
  script_mandatory_keys("Microsoft/ForefrontServerProtection/Ver");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
key = "";
ediVer = "";
exeVer = "";
exchangePath = "";

## Confirm Forefront Protection
if(!ediVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Confirm the Exchange Server
if(!registry_key_exists(key:"SOFTWARE\Microsoft\Exchange") &&
   !registry_key_exists(key:"SOFTWARE\Microsoft\ExchangeServer")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Exchange\";

## Get the install path
exchangePath = registry_get_sz(key: key, item:"InstallLocation");

## exit if not get install path
if(!exchangePath){
  exit(0);
}

exchangePath = exchangePath + "\TransportRoles\agents\FSEAgent\bin";

## Get Version from Microsoft.fss.antispam.dll file version
exeVer = fetch_file_version(sysPath:exchangePath, file_name:"Microsoft.fss.antispam.dll");
if(!exeVer){
  exit(0);
}

if(version_is_less(version:exeVer, test_version:"11.0.747.0"))
{
  security_message(0);
  exit(0);
}
