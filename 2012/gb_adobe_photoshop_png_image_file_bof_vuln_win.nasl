###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_photoshop_png_image_file_bof_vuln_win.nasl 5963 2017-04-18 09:02:14Z teissa $
#
# Adobe Photoshop PNG Image Processing Buffer Overflow Vulnerabilities (Windows)
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
tag_affected = "Adobe Photoshop version CS6 (13.0) on Windows";
tag_insight = "- A boundary error in the 'Standard MultiPlugin.8BF' module fails to
    process a Portable Network Graphics (PNG) image, which allows attacker to
    cause a buffer overflow via a specially crafted 'tRNS' chunk size.
  - Improper validation in Photoshop.exe when decompressing
    SGI24LogLum-compressed TIFF images.";
tag_solution = "Upgrade to Adobe Photoshop version CS6 (13.0.1) or later,
  For updates refer to http://www.adobe.com/downloads/";
tag_summary = "This host is installed with Adobe Photoshop and is prone to buffer
  overflow vulnerabilities.";

if(description)
{
  script_id(803025);
  script_version("$Revision: 5963 $");
  script_cve_id("CVE-2012-4170", "CVE-2012-0275");
  script_bugtraq_id(55333, 55372);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-04-18 11:02:14 +0200 (Tue, 18 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-09-03 16:36:21 +0530 (Mon, 03 Sep 2012)");
  script_name("Adobe Photoshop PNG Image Processing Buffer Overflow Vulnerabilities (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49141");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-20.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl", "gb_adobe_photoshop_detect.nasl");
  script_require_keys("Adobe/Photoshop/Ver");
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
appkey = "";
appPath = "";

## Check for adobe versions CS6
adobeVer = get_kb_item("Adobe/Photoshop/Ver");
if(!adobeVer || "CS6" >!< adobeVer){
  exit(0);
}

adobeVer = eregmatch(pattern:"CS([0-9.]+) ?([0-9.]+)", string: adobeVer);

## Check for Adobe Photoshop versions without patch
## Adobe Photoshop CS6 (13.0)
if(adobeVer[2] && version_is_equal(version:adobeVer[2] , test_version:"13.0")){
  security_message(0);
}
