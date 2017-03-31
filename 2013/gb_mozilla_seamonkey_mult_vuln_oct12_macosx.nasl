###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_seamonkey_mult_vuln_oct12_macosx.nasl 2924 2016-03-23 11:28:16Z benallard $
#
# Mozilla Seamonkey Multiple Vulnerabilities - Oct 12 (Mac OS X)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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

tag_impact = "Successful exploitation will let attackers to conduct cross-site scripting,
  clickjacking attacks or cause a denial of service or possibly execute
  arbitrary code.
  Impact Level: System/Application";

tag_affected = "SeaMonkey versions before 2.13 on Mac OS X";
tag_insight = "The flaws are due to
  - An error while handling navigation away from a web page that has multiple
    menus of SELECT elements active, which allows remote attackers to conduct
    clickjacking attacks.
  - An invalid cast when using the instance of operator on certain types of
    JavaScript objects.
  - An error when implementing the HTML5 Same Origin Policy, which allows
    remote attackers to conduct cross-site scripting (XSS) attacks by
    leveraging initial-origin access after document.domain has been set.";
tag_solution = "Upgrade to SeaMonkey version 2.13 or later,
  For updates refer to http://www.mozilla.org/projects/seamonkey";
tag_summary = "The host is installed with Mozilla Seamonkey and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803659);
  script_version("$Revision: 2924 $");
  script_cve_id("CVE-2012-5354", "CVE-2012-3989", "CVE-2012-3985", "CVE-2012-3984");
  script_bugtraq_id(55856);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-03-23 12:28:16 +0100 (Wed, 23 Mar 2016) $");
  script_tag(name:"creation_date", value:"2013-07-12 12:05:08 +0530 (Fri, 12 Jul 2013)");
  script_name("Mozilla Seamonkey Multiple Vulnerabilities - Oct 12 (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50856");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50935");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-76.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-75.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-80.html");
  script_summary("Check for the vulnerable version of Mozilla SeaMonkey on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("SeaMonkey/MacOSX/Version");
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

# Variable Initialization
seaVer = "";

# SeaMonkey Check
seaVer = get_kb_item("SeaMonkey/MacOSX/Version");
if(seaVer)
{
  # Grep for SeaMonkey version
  if(version_is_less(version:seaVer, test_version:"2.13"))
  {
    security_message(0);
    exit(0);
  }
}
