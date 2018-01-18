###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_photoshop_insecure_lib_load_vuln.nasl 8438 2018-01-16 17:38:23Z teissa $
#
# Adobe Photoshop Insecure Library Loading Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow remote attackers to execute
arbitrary code and conduct DLL hijacking attacks.

Impact Level: Application";

tag_affected = "Adobe Photoshop CS2 through CS5";

tag_insight = "The flaw is caused by application insecurely loading certain
librairies from the current working directory, which could allow attackers to
execute arbitrary code by tricking a user into opening a file from a network share.";

tag_solution = "Apply Adobe Photoshop 12.0.3 update for Adobe Photoshop CS5.
For updates refer to http://www.adobe.com/downloads/";

tag_summary = "This host is installed with Adobe Photoshop and is prone to
Insecure Library Loading vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901147");
  script_version("$Revision: 8438 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-09-01 09:34:36 +0200 (Wed, 01 Sep 2010)");
  script_cve_id("CVE-2010-3127");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Photoshop Insecure Library Loading Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41060");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2170");
  script_xref(name : "URL" , value : "http://blog.zoller.lu/2010/08/cve-2010-xn-loadlibrarygetprocaddress.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect.nasl");
  script_mandatory_keys("Adobe/Photoshop/Ver");
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
if(!adobeVer || !(adobeVer =~ "CS[1-5]")){
  exit(0);
}

adobeVer = eregmatch(pattern:"(CS([0-9.]+)) ?([0-9.]+)", string: adobeVer);

if(!isnull(adobeVer[1]))
{
  ##Grep for Adobe Photoshop CS2 through CS5
  if( version_in_range(version:adobeVer[1], test_version: "CS2", test_version2: "CS5") ){
    security_message(0);
  }
}
