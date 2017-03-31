###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_photoshop_gif_mem_corruption_vuln.nasl 3949 2016-09-02 13:45:51Z cfi $
#
# Adobe Photoshop '.GIF' File Processing Memory Corruption Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_solution = "Apply patch APSB11-22 for Adobe Photoshop CS5 and CS5.1
  For updates refer to http://www.adobe.com/support/security/bulletins/apsb11-22.html

  *****
  NOTE: Ignore this warning if patch is applied already.
  *****";

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code and cause Denial of Service.
  Impact Level: System/Application";
tag_affected = "Adobe Photoshop CS5 through CS5.1";
tag_insight = "The flaw is caused by memory corruptions error when processing a crafted
  '.GIF' file.";
tag_summary = "This host is installed with Adobe Photoshop and is prone to
  remote code execution vulnerability.";

if(description)
{
  script_id(902618);
  script_version("$Revision: 3949 $");
  script_tag(name:"last_modification", value:"$Date: 2016-09-02 15:45:51 +0200 (Fri, 02 Sep 2016) $");
  script_tag(name:"creation_date", value:"2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)");
  script_cve_id("CVE-2011-2131");
  script_bugtraq_id(49106);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Photoshop '.GIF' File Processing Memory Corruption Vulnerability");

  script_xref(name : "URL" , value : "http://securitytracker.com/id/1025910");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45587/");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb11-22.html");

  script_tag(name:"qod_type", value:"registry");
  script_summary("Check for the version of Adobe Photoshop");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect.nasl");
  script_require_keys("Adobe/Photoshop/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("version_func.inc");

## Variable Initiliazation
adobeVer = "";

## Get version from KB
## Check for adobe versions CS5 and CS5.1
adobeVer = get_kb_item("Adobe/Photoshop/Ver");
if(!adobeVer || "CS5" >!< adobeVer){
  exit(0);
}

adobeVer = eregmatch(pattern:"CS([0-9.]+) ?([0-9.]+)", string: adobeVer);

if(!isnull(adobeVer[2]))
{
  ## Grep for Adobe Photoshop 12.0 and 12.1
  if(version_is_equal(version:adobeVer[2], test_version:"12.0") ||
     version_is_equal(version:adobeVer[2], test_version:"12.1")){
    security_message(0);
  }
}
