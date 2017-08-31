###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_dos_vuln_feb14_macosx.nasl 6735 2017-07-17 09:56:49Z teissa $
#
# Mozilla Firefox Cookie Verification Denial of Service Vulnerability (Mac OS X)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:firefox";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804502";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6735 $");
  script_cve_id("CVE-2013-6167");
  script_bugtraq_id(62969);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-17 11:56:49 +0200 (Mon, 17 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-02-19 11:18:41 +0530 (Wed, 19 Feb 2014)");
  script_name("Mozilla Firefox Cookie Verification Denial of Service Vulnerability (Mac OS X)");

  tag_summary =
"This host is installed with Mozilla Firefox and is prone to denial of service
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaw is due to improper handling of the browser.cookie cookie header.";

  tag_impact =
"Successful exploitation will allow attackers to terminate a user's session on
a website, which will not allow the attacker to log back in to the website
until after the browser has been restarted.

Impact Level: Application";

  tag_affected =
"Mozilla Firefox version 19.0 on Mac OS X";

  tag_solution =
"No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2013/q4/121");
  script_xref(name : "URL" , value : "http://redmine.lighttpd.net/issues/2188");
  script_xref(name : "URL" , value : "https://bugzilla.mozilla.org/show_bug.cgi?id=858215");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
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
if(version_is_equal(version:ffVer, test_version:"19.0"))
{
  security_message(0);
  exit(0);
}
