###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_itunes_mult_vuln_jun13_macosx.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Apple iTunes Multiple Vulnerabilities - June13 (Mac OS X)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code,
  conduct Man-in-the-Middle (MitM) attack or cause heap-based buffer overflow.
  Impact Level: System/Application";

tag_summary = "This host is installed with Apple iTunes and is prone to
  multiple vulnerabilities.";
tag_solution = "Upgrade to version 11.0.3 or later,
  For updates refer to http://www.apple.com/itunes/download";
tag_insight = "Multiple flaws due to
  - Improper validation of SSL certificates.
  - Integer overflow error within the 'string.replace()' method.
  - Some vulnerabilities are due to a bundled vulnerable version of WebKit.
  - Array indexing error when handling JSArray objects.
  - Boundary error within the 'string.concat()' method.";
tag_affected = "Apple iTunes before 11.0.3 on Mac OS X";

if(description)
{
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_oid("1.3.6.1.4.1.25623.1.0.803807");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-1014", "CVE-2013-1011", "CVE-2013-1010", "CVE-2013-1008",
                "CVE-2013-1007", "CVE-2013-1006", "CVE-2013-1005", "CVE-2013-1004",
                "CVE-2013-1003", "CVE-2013-1002", "CVE-2013-1001", "CVE-2013-1000",
                "CVE-2013-0999", "CVE-2013-0998", "CVE-2013-0997", "CVE-2013-0996",
                "CVE-2013-0995", "CVE-2013-0994", "CVE-2013-0993", "CVE-2013-0992",
                                                                   "CVE-2013-0991");
  script_bugtraq_id(59941, 59974, 59976, 59977, 59970, 59973, 59972, 59971,
                    59967, 59965, 59964, 59963, 59960, 59959, 59958, 59957,
                                         59956, 59955, 59954, 59953, 59944);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-06-06 13:03:34 +0530 (Thu, 06 Jun 2013)");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Apple iTunes Multiple Vulnerabilities - June13 (Mac OS X)");

  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT5766");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53471");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2013/May/msg00000.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_itunes_detect_macosx.nasl");
  script_mandatory_keys("Apple/iTunes/MacOSX/Version");
  exit(0);
}

include("version_func.inc");

## Variable Initialization
ituneVer = "";

##Get the version from kb
ituneVer= get_kb_item("Apple/iTunes/MacOSX/Version");
if(!ituneVer){
  exit(0);
}

## Check for the vulnerable version
if(version_is_less(version:ituneVer, test_version:"11.0.3"))
{
  security_message(0);
  exit(0);
}

