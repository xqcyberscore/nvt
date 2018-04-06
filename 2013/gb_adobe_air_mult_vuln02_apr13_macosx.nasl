###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_air_mult_vuln02_apr13_macosx.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Adobe AIR Multiple Vulnerabilities -02 April 13 (Mac OS X)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code or cause  denial-of-service condition.
  Impact Level: System/Application";

tag_affected = "Adobe AIR Version 3.6.0.6090 and prior on Windows";
tag_insight = "Multiple flaws due to,
  - Error when initializing certain pointer arrays.
  - Integer overflow error.";
tag_solution = "Upgrade to version 3.7.0.1530 or later,
  For updates refer to http://get.adobe.com/air";
tag_summary = "This host is installed with Adobe AIR and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803386");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-1380","CVE-2013-1379","CVE-2013-1378","CVE-2013-2555");
  script_bugtraq_id(58949, 58951, 58947, 58396);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-04-19 11:30:01 +0530 (Fri, 19 Apr 2013)");
  script_name("Adobe AIR Multiple Vulnerabilities -02 April 13 (Mac OS X)");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/52931");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb13-11.html");
  script_xref(name : "URL" , value : "http://www.cert.be/pro/advisories/adobe-flash-player-air-multiple-vulnerabilities-3");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Air/MacOSX/Version");
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
playerVer = "";

# Check for Adobe AIR version prior to 3.6.0.6090
playerVer = get_kb_item("Adobe/Air/MacOSX/Version");
if(playerVer != NULL)
{
  if(version_is_less_equal(version:playerVer, test_version:"3.6.0.6090"))
  {
    security_message(0);
    exit(0);
  }
}
