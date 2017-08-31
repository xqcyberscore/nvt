###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_live_meeting_ms14-036.nasl 6750 2017-07-18 09:56:47Z teissa $
#
# Microsoft Live Meeting Remote Code Execution Vulnerability (2967487)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:microsoft:office_live_meeting";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804598");
  script_version("$Revision: 6750 $");
  script_cve_id("CVE-2014-1817", "CVE-2014-1818");
  script_bugtraq_id(67897, 67904);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-18 11:56:47 +0200 (Tue, 18 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-06-11 15:48:21 +0530 (Wed, 11 Jun 2014)");
  script_name("Microsoft Live Meeting Remote Code Execution Vulnerability (2967487)");

  tag_summary =
"This host is missing a critical security update according to Microsoft
Bulletin MS14-036.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Multiple flaws are due to,
- An error within Unicode Scripts Processor.
- An error within GDI+ when validating images.";

  tag_impact =
"Successful exploitation will allow attackers to execute arbitrary code
and compromise a user's system.

Impact Level: System/Application";

  tag_affected =
"Microsoft Live Meeting 2007 Console";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and
update mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms14-036";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/58583");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2957503");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2957509");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/ms14-036");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_live_meeting_detect.nasl");
  script_mandatory_keys("MS/OfficeLiveMeeting/Ver");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

## Variables Initialization
appPath = "";
dllVer = "";

## get the Install Location
appPath = get_app_location(cpe:CPE);
if(!appPath ||  "Couldn find the install location" >< appPath){
  exit(0);
}

## Get Version from Ogl.dll
dllVer = fetch_file_version(sysPath:appPath, file_name:"Ogl.dll");
if(!dllVer){
  exit(0);
}

## Check for Ogl.dll version
if(version_is_less(version:dllVer, test_version:"12.0.6700.5000"))
{
  security_message(0);
  exit(0);
}
