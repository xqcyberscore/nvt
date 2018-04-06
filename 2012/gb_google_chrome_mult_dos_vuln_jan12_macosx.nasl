###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_dos_vuln_jan12_macosx.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Google Chrome Multiple Denial of Service Vulnerabilities - January12 (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code,
  cause a denial of service.
  Impact Level: Application";
tag_affected = "Google Chrome version prior to 16.0.912.75 on Mac OS X";
tag_insight = "Multiple flaws are due to,
  - A use-after-free error when the handling of animation frames.
  - A boundary error within the 'xmlStringLenDecodeEntities()' function of
    libxml2
  - A stack based buffer overflow error in glyph handling.";
tag_solution = "Upgrade to the Google Chrome 16.0.912.75 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "The host is installed with Google Chrome and is prone to multiple
  denial of service vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802376");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2011-3919", "CVE-2011-3921", "CVE-2011-3922");
  script_bugtraq_id(51300);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-01-10 15:35:57 +0530 (Tue, 10 Jan 2012)");
  script_name("Google Chrome Multiple Denial of Service Vulnerabilities - January12 (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47449/");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.com/2012/01/stable-channel-update.html");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_require_keys("GoogleChrome/MacOSX/Version");
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

## Get the version from KB
chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome Versions prior to 16.0.912.75
if(version_is_less(version:chromeVer, test_version:"16.0.912.75")){
  security_message(0);
}
