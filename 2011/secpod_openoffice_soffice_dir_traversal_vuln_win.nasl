###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openoffice_soffice_dir_traversal_vuln_win.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# OpenOffice.org 'soffice' Directory Traversal Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation could allows local users to gain privileges via
  a Trojan horse shared library in the current working directory.
  Impact Level: System/Application";
tag_affected = "OpenOffice Version 3.x to 3.2.0 on Windows";
tag_insight = "The flaw is due to an error in 'soffice', which places a zero-length
  directory name in the 'LD_LIBRARY_PATH'.";
tag_solution = "Upgrade to OpenOffice Version 3.3.0 or later
  For updates refer to http://www.openoffice.org/";
tag_summary = "The host has OpenOffice installed and is prone to directory
  traversal vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902284");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-02-05 04:12:38 +0100 (Sat, 05 Feb 2011)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-3689");
  script_bugtraq_id(46031);
  script_name("OpenOffice.org 'soffice' Directory Traversal Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43065");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0232");
  script_xref(name : "URL" , value : "http://www.cs.brown.edu/people/drosenbe/research.html");
  script_xref(name : "URL" , value : "http://www.openoffice.org/security/cves/CVE-2010-3689.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("secpod_openoffice_detect_win.nasl");
  script_require_keys("OpenOffice/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

##  Get the version from KB
openVer = get_kb_item("OpenOffice/Win/Ver");

## Exit if script fails to get the version
if(!openVer){
  exit(0);
}

## Check the version from 3.0 to 3.2
if(openVer =~ "^3.*")
{
  ## OpenOffice 3.3 (3.3.9567)
  if(version_is_less(version:openVer, test_version:"3.3.9567")){
    security_message(0);
  }
}
