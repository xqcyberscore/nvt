###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_thunderbird_mult_vuln_oct12_macosx.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Mozilla Thunderbird Multiple Vulnerabilities - Oct 12 (Mac OS X)
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

tag_affected = "Thunderbird versions before 16.0 on Mac OS X";
tag_insight = "The flaws are due to
  - An error while handling navigation away from a web page that has multiple
    menus of SELECT elements active, which allows remote attackers to conduct
    clickjacking attacks.
  - An invalid cast when using the instance of operator on certain types of
    JavaScript objects.
  - An error when implementing the HTML5 Same Origin Policy, which allows
    remote attackers to conduct cross-site scripting (XSS) attacks by
    leveraging initial-origin access after document.domain has been set.";
tag_solution = "Upgrade to Thunderbird version 16.0 or later,
  For updates refer to http://www.mozilla.org/en-US/thunderbird";
tag_summary = "The host is installed with Mozilla Thunderbird and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803658");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2012-5354", "CVE-2012-3989", "CVE-2012-3985", "CVE-2012-3984");
  script_bugtraq_id(55856);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-07-12 11:45:08 +0530 (Fri, 12 Jul 2013)");
  script_name("Mozilla Thunderbird Multiple Vulnerabilities - Oct 12 (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50856");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50935");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-76.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-75.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-80.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("ThunderBird/MacOSX/Version");
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
tbVer = "";

# Thunderbird Check
tbVer = get_kb_item("ThunderBird/MacOSX/Version");
if(tbVer)
{
  # Grep for Thunderbird version
  if(version_is_less(version:tbVer, test_version:"16.0")){
    security_message(0);
    exit(0);
  }
}
