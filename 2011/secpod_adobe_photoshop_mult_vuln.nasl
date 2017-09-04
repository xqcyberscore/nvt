###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_photoshop_mult_vuln.nasl 7024 2017-08-30 11:51:43Z teissa $
#
# Adobe Photoshop Multiple Vulnerabilities.
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation could allow attackers to crash the application to
  cause denial of service.
  Impact Level: Application/System";
tag_affected = "Adobe Photoshop CS5 before 12.0.4";
tag_insight = "Multiple flaws are present due to errors in Liquify save mesh, Sharpen,
  Quick Selection, and Orphea Studio File Info.";
tag_solution = "Upgrade to Adobe Photoshop CS5 12.0.4 or later,
  For updates refer to http://www.adobe.com/support/downloads/thankyou.jsp?ftpID=4973&fileID=4688";
tag_summary = "This host is installed with Adobe Photoshop and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(902374);
  script_version("$Revision: 7024 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-30 13:51:43 +0200 (Wed, 30 Aug 2017) $");
  script_tag(name:"creation_date", value:"2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)");
  script_cve_id("CVE-2011-2164");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Adobe Photoshop Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1025483");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/downloads/detail.jsp?ftpID=4973");
  script_xref(name : "URL" , value : "http://blogs.adobe.com/jnack/2011/05/photoshop-12-0-4-update-for-cs5-arrives.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect.nasl");
  script_require_keys("Adobe/Photoshop/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
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
  ##Grep for Adobe Photoshop CS5 before 12.0.4
  if(version_is_less(version:adobeVer[2], test_version:"12.0.4") ){
    security_message(0);
  }
}
