###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_dos_vuln_apr13_macosx.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Google Chrome Denial of Service Vulnerability - April 13 (Mac OS X)
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

tag_impact = "Successful exploitation could allow attackers to cause denial-of-service.
  Impact Level: Application";

tag_affected = "Google Chrome version prior to 27.0.1444.3 on MAC OS X";
tag_insight = "User-supplied input is not properly sanitized when parsing JavaScript in
  'Google V8' JavaScript Engine.";
tag_solution = "Upgrade to the Google Chrome 27.0.1444.3 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "The host is running Google Chrome and is prone to denial of
  service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803357");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-2632");
  script_bugtraq_id(58697);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-04-02 11:31:23 +0530 (Tue, 02 Apr 2013)");
  script_name("Google Chrome Denial of Service Vulnerability - April 13 (Mac OS X)");
  script_xref(name : "URL" , value : "http://cxsecurity.com/cveshow/CVE-2013-2632");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2013/03/dev-channel-update_18.html");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
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
chromeVer = "";

## Get the version from KB
chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome Version less than 27.0.1444.3
if(version_is_less(version:chromeVer, test_version:"27.0.1444.3"))
{
  security_message(0);
  exit(0);
}
