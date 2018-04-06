###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_feb12_macosx01.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Google Chrome Multiple Vulnerabilities - February 12 (MAC OS X 01)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation could allow attackers to cause a denial of service.
  Impact Level: Application";
tag_affected = "Google Chrome version prior to 17.0.963.56 on MAC OS X";
tag_insight = "The flaws are due to
  - An integer overflow in libpng, PDF codecs.
  - Bad cast in column handling.
  - Out-of-bounds read in h.264 parsing.
  - Use-after-free with drag and drop.
  - Use-after-free in subframe loading.
  - An error within Native Client validator implementation.
  - Heap buffer overflow while handling MVK file.
  - Use-after-free error while handling database.
  - Heap overflow in path rendering.";
tag_solution = "Upgrade to the Google Chrome 17.0.963.56 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "The host is installed with Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802599");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2011-3026", "CVE-2011-3015", "CVE-2011-3027", "CVE-2011-3025",
                "CVE-2011-3024", "CVE-2011-3023", "CVE-2011-3021", "CVE-2011-3020",
                "CVE-2011-3019", "CVE-2011-3016", "CVE-2011-3017", "CVE-2011-3018");
  script_bugtraq_id(52049, 52031);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-02-21 15:06:35 +0530 (Tue, 21 Feb 2012)");
  script_name("Google Chrome Multiple Vulnerabilities - February 12 (MAC OS X 01)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48016/");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2012/02/chrome-stable-update.html");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
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
chromeVer = NULL;

## Get the version from KB
chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome Versions prior to 17.0.963.56
if(version_is_less(version:chromeVer, test_version:"17.0.963.56")){
  security_message(0);
}
