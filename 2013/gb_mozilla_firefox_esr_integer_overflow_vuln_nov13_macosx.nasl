###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_esr_integer_overflow_vuln_nov13_macosx.nasl 31965 2013-11-07 13:47:17Z nov$
#
# Mozilla Firefox ESR Integer Overflow Vulnerability-01 Nov13 (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
CPE = "cpe:/a:mozilla:firefox_esr";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804154";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6115 $");
  script_cve_id("CVE-2013-5607");
  script_bugtraq_id(63802);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-05-12 11:03:25 +0200 (Fri, 12 May 2017) $");
  script_tag(name:"creation_date", value:"2013-11-26 09:47:20 +0530 (Tue, 26 Nov 2013)");
  script_name("Mozilla Firefox ESR Integer Overflow Vulnerability-01 Nov13 (Mac OS X)");

  tag_summary =
"This host is installed with Mozilla Firefox ESR and is prone to integer
overflow vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw is due to integer overflow in the 'PL_ArenaAllocate' function
in Mozilla Netscape Portable Runtime (NSPR).";

  tag_impact =
"Successful exploitation will allow remote attackers to cause a denial of
service (application crash) or possibly have unspecified other impact.

Impact Level: Application.";

  tag_affected =
"Mozilla Firefox ESR version 17.x before 17.0.11 and 24.x before 24.1.1 on
Mac OS X";

  tag_solution =
"Upgrade to Mozilla Firefox ESR version 17.0.11 or 24.1.1 or later,
For updates refer to http://www.mozilla.org/en-US/firefox/organizations/all.html";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/55732");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2013/mfsa2013-103.html");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/current/0105.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
ffVer = "";

## Get version
if(!ffVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

# Check for vulnerable version
if(version_in_range(version:ffVer, test_version:"17.0", test_version2:"17.0.10") ||
   version_in_range(version:ffVer, test_version:"24.0", test_version2:"24.1.0"))
{
  security_message(0);
  exit(0);
}
