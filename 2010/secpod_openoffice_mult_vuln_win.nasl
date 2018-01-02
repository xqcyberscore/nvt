###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openoffice_mult_vuln_win.nasl 8207 2017-12-21 07:30:12Z teissa $
#
# OpenOffice.org Buffer Overflow and Directory Traversal Vulnerabilities (Windows)
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

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code in the context of the application. Failed exploit attempts will crash
  the application.
  Impact Level: System/Application";
tag_affected = "OpenOffice Version 2.x and 3.x to 3.2.0 on windows.";
tag_insight = "Multiple flaws are due to:
  - A buffer overflow error when processing malformed TGA files and PNG files
  - A memory corruption error within the 'WW8ListManager::WW8ListManager()'
    and 'WW8DopTypography::ReadFromMem()' function when processing malformed
    data
  - A memory corruption error when processing malformed RTF data
  - A directory traversal error related to 'zip/jar' package extraction
  - A buffer overflow error when processing malformed PPT files";
tag_solution = "Upgrade to OpenOffice Version 3.3.0 or later
  For updates refer to http://www.openoffice.org/";
tag_summary = "The host has OpenOffice installed and is prone to buffer overflow
  and directory traversal vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902283");
  script_version("$Revision: 8207 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 08:30:12 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-08-30 16:09:21 +0200 (Mon, 30 Aug 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-3450", "CVE-2010-3451", "CVE-2010-3452", "CVE-2010-3453",
                "CVE-2010-3454", "CVE-2010-4253", "CVE-2010-4643");
  script_bugtraq_id(46031);
  script_name("OpenOffice.org Buffer Overflow and Directory Traversal Vulnerabilities (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43065");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0230");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0232");
  script_xref(name : "URL" , value : "http://www.cs.brown.edu/people/drosenbe/research.html");

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

## check for the version 2.x
if(openVer =~ "^2.*")
{
  security_message(0);
  exit(0);
}

## Check the version from 3.0 to 3.3.9567
if(openVer =~ "^3.*")
{
  ## OpenOffice 3.3 (3.3.9567)
  if(version_is_less(version:openVer, test_version:"3.3.9567")){
    security_message(0);
  }
}
