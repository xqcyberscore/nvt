###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_ie_memory_corruption_vuln.nasl 6086 2017-05-09 09:03:30Z teissa $
#
# Microsoft Internet Explorer Memory Corruption Vulnerability (2755801)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.903213";
CPE = "cpe:/a:microsoft:ie";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6086 $");
  script_cve_id("CVE-2013-3343");
  script_bugtraq_id(60478);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-05-09 11:03:30 +0200 (Tue, 09 May 2017) $");
  script_tag(name:"creation_date", value:"2013-06-12 16:51:29 +0530 (Wed, 12 Jun 2013)");
  script_name("Microsoft Internet Explorer Memory Corruption Vulnerability (2755801)");

  tag_summary =
"This host is missing a security update according to Microsoft Security
Advisory (2755801).";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Unspecified flaw due to improper sanitization of user-supplied input.";

  tag_impact =
"Successful exploitation will allow attackers to execute arbitrary code,
corrupt memory or cause a denial of service condition.

Impact Level: System/Application";

  tag_affected =
"Microsoft Windows 8
Microsoft Windows 8.1
Microsoft Windows Server 2012";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
http://technet.microsoft.com/en-us/security/advisory/2755801";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2847928");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/advisory/2755801");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb13-16.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

## Variables Initialization
sysPath = "";
ieVer = "";
flashVer  = NULL;

## Check for OS and Service Pack
if(hotfix_check_sp(win8:1, win2012:1, win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}
## Check for IE
ieVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID);

if(!ieVer || !(ieVer =~ "^(10\.|11\.)")){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from Flash.ocx
flashVer = fetch_file_version(sysPath, file_name:"system32\Macromed\Flash\Flash.ocx");
if(!flashVer){
  exit(0);
}
## Check for Flash.ocx version
if(version_is_less(version:flashVer, test_version:"11.9.900.170"))
{
  security_message(0);
  exit(0);
}
