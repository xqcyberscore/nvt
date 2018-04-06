###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_photoshop_camera_raw_code_exec_vuln_win.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Adobe Photoshop Camera Raw Plug-in Code Execution Vulnerabilities (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code.
  Impact Level: System/Application";
tag_affected = "Adobe Photoshop Camera Raw Plug-in version before 7.3 on Windows";
tag_insight = "Errors exists within the 'Camera Raw.8bi' plug-in when
  - Parsing a LZW compressed TIFF images can be exploited to cause a buffer
    underflow via a specially crafted LZW code within an image row strip.
  - Allocating memory during TIFF image processing can be exploited to cause
    buffer overflow via a specially crafted image dimensions.";
tag_solution = "Upgrade to Adobe Photoshop Camera Raw Plug-in version 7.3 or later,
  For updates refer to http://www.adobe.com/downloads/";
tag_summary = "This host is installed with Adobe Photoshop Camera Raw Plug-in and
  is prone to code execution vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803081");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-5679", "CVE-2012-5680");
  script_bugtraq_id(56922, 56924);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-12-21 13:17:09 +0530 (Fri, 21 Dec 2012)");
  script_name("Adobe Photoshop Camera Raw Plug-in Code Execution Vulnerabilities (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49929");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027872");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-28.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect.nasl");
  script_mandatory_keys("Adobe/Photoshop/Ver");
  script_require_ports(139, 445);
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
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initiliazation
photoVer = "";
adobeVer = "";
sysPath = "";
camrawVer = "";
camrawPath = "";

## Check for adobe versions CS6
photoVer = get_kb_item("Adobe/Photoshop/Ver");
if(!photoVer){
  exit(0);
}

if(photoVer =~ "CS")
{
  adobeVer = eregmatch(pattern:"CS[0-9.]+", string: photoVer);
  if(!isnull(adobeVer[0]))
     photoVer = adobeVer[0];
}

## Get the System Common Files Directory
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                        item:"CommonFilesDir");
if(isnull(sysPath)){
   exit(0);
}

## Get the Adobe Photoshop Plug-Ins directory Path
## Check for Camera Raw.8bi File
camrawPath = sysPath + "\Adobe\Plug-Ins\"+ photoVer +"\File Formats";
camrawVer = fetch_file_version(sysPath: camrawPath, file_name:"Camera Raw.8bi");

##Check for Camera Raw.8bi version less than 7.3
if(!isnull(camrawVer) &&
   version_is_less(version: camrawVer, test_version:"7.3")){
  security_message(0);
}
