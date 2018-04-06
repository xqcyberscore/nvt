###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_sketchup_skp_file_code_exec_vuln_macosx.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Google SketchUp '.SKP' File Remote Code Execution Vulnerability (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow attackers to cause SketchUp to exit
  unexpectedly and execute arbitrary code by tricking a user into opening a
  specially crafted '.SKP' file.
  Impact Level: System/Application";
tag_affected = "Google SketchUp version 7.1 Maintenance Release 2 and prior on Mac OS X";
tag_insight = "The flaw is due to an error when handling certain types of invalid
  edge geometry in a specially crafted SketchUp (.SKP) file.";
tag_solution = "Upgrade to Google SketchUp version 8.0 or later,
  For updates refer to http://sketchup.google.com/download/index2.html";
tag_summary = "This host is installed with Google SketchUp and is prone to
  to remote code execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902681");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2011-2478");
  script_bugtraq_id(48363);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-05-21 14:56:42 +0530 (Mon, 21 May 2012)");
  script_name("Google SketchUp '.SKP' File Remote Code Execution Vulnerability (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38187");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/68147");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/msvr/msvr11-006");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 SecPod");
  script_family("General");
  script_dependencies("secpod_google_sketchup_detect_macosx.nasl");
  script_require_keys("Google/SketchUp/MacOSX/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
gsVer = "";

## Get the version from KB
gsVer = get_kb_item("Google/SketchUp/MacOSX/Version");
if(!gsVer){
  exit(0);
}

# Check for Google SketchUp 7.1 m2 (7.1.6859) and prior
if(version_is_less_equal(version:gsVer, test_version:"7.1.6859")){
  security_message(0);
}
