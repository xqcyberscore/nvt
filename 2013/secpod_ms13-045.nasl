###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-045.nasl 9323 2018-04-05 08:44:52Z cfischer $
#
# Windows Essentials Information Disclosure Vulnerability (2813707)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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

CPE = "cpe:/a:microsoft:windows_essentials";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903210");
  script_version("$Revision: 9323 $");
  script_cve_id("CVE-2013-0096");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-05 10:44:52 +0200 (Thu, 05 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-05-15 16:30:40 +0530 (Wed, 15 May 2013)");
  script_name("Windows Essentials Information Disclosure Vulnerability (2813707)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2813707");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-045");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_windows_live_essentials_detect.nasl");
  script_mandatory_keys("Windows/Essentials6432/Installed");

  tag_impact = "Successful exploitation allow attackers to overwrite arbitrary files and
  could led to launch further attacks.

  Impact Level: System/Application";

  tag_affected = "Windows Essentials 2012 and prior";

  tag_insight = "The flaw is due to insufficient validation of user-supplied input processed
  by the Windows Writer component.";

  tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,

  http://technet.microsoft.com/en-us/security/bulletin/ms13-045";

  tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS13-045.";

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
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
winVer = infos['version'];
winLoc = infos['location'];
if(!winLoc || "Could not find the install location" >< winLoc){
  exit(0);
}

exeVer = fetch_file_version(sysPath:winLoc, file_name:"Installer\wlarp.exe");
if(exeVer) {
  if(version_is_less(version:exeVer, test_version:"16.4.3508.205")) {
    security_message(0);
    exit(0);
  }
}

exit(99);