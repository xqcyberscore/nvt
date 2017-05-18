###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_photoshop_bof_n_use_after_free_vuln_win.nasl 5950 2017-04-13 09:02:06Z teissa $
#
# Adobe Photoshop BOF and Use After Free Vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_solution = "Apply patch for Adobe Photoshop CS5 and CS5.1,
  For updates refer to http://helpx.adobe.com/photoshop/kb/security-update-photoshop.html

  Or upgrade to Adobe Photoshop version CS6 or later,
  For updates refer to http://www.adobe.com/downloads/";

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code.
  Impact Level: Application/System";
tag_affected = "Adobe Photoshop version prior to CS6 on Windows";
tag_insight = "The flaws are caused by
  - An insufficient input validation while decompressing TIFF images.
  - An input sanitisation error when parsing TIFF images can be exploited
    to cause a heap-based buffer overflow via a specially crafted file.";
tag_summary = "This host is installed with Adobe Photoshop and is prone to buffer
  overflow and use after free vulnerabilities.";

if(description)
{
  script_id(802782);
  script_version("$Revision: 5950 $");
  script_cve_id("CVE-2012-2027", "CVE-2012-2028", "CVE-2012-2052", "CVE-2012-0275");
  script_bugtraq_id(53421, 52634, 53464, 55372);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-04-13 11:02:06 +0200 (Thu, 13 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-05-15 15:41:49 +0530 (Tue, 15 May 2012)");
  script_name("Adobe Photoshop BOF and Use After Free Vulnerabilities (Windows)");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/48457/");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027046");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-11.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl", "gb_adobe_photoshop_detect.nasl");
  script_require_keys("Adobe/Photoshop/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initiliazation
photoVer = "";
version = "";
appkey = "";
appPath = "";

## Check application is installed
photoVer = get_kb_item("Adobe/Photoshop/Ver");
if(!photoVer){
  exit(0);
}

if("CS" >< photoVer)
{
  version = eregmatch(pattern:"CS([0-9.]+) ([0-9.]+)", string:photoVer);
  if(version[2]){
    photoVer = version[2];
  }
}

## Check for Adobe Photoshop versions with patch
## Adobe Photoshop CS5 (12.0.5) and CS5.1 (12.1.1)
if(version_is_less(version:photoVer, test_version:"12.0.5"))
{
  security_message(0);
  exit(0);
}

if("12.1" >< photoVer)
{
  if(version_is_less(version:photoVer, test_version:"12.1.1")){
    security_message(0);
  }
}
