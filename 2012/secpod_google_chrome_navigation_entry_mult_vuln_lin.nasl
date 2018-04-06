###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_navigation_entry_mult_vuln_lin.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Google Chrome Multiple Vulnerabilities - Jan12 (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code or
  cause a denial of service.
  Impact Level: Application";
tag_affected = "Google Chrome version prior to 16.0.912.77 on Linux";
tag_insight = "Multiple flaws are due to an,
  - Use-after-free error and it is related to DOM selections and DOM handling.
  - Use-after-free error in the Safe Browsing feature and it is related to
    a navigation entry and an interstitial page.
  - Heap-based buffer overflow in the tree builder, allows remote attackers
    to cause a denial of service.
  - Error in Skia, does not perform all required initialization of values.";
tag_solution = "Upgrade to the Google Chrome 16.0.912.77 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "The host is installed with Google Chrome and is prone multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902904");
  script_version("$Revision: 9352 $");
  script_bugtraq_id(51641);
  script_cve_id("CVE-2011-3924", "CVE-2011-3925", "CVE-2011-3926", "CVE-2011-3927",
                "CVE-2011-3928");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-01-25 13:11:21 +0530 (Wed, 25 Jan 2012)");
  script_name("Google Chrome Multiple Vulnerabilities - Jan12 (Linux)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47694/");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1026569");
  script_xref(name : "URL" , value : "http://code.google.com/p/chromium/issues/detail?id=108461");
  script_xref(name : "URL" , value : "http://securityorb.com/2012/01/google-releases-chrome-16-0-912-77/");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.com/2012/01/stable-channel-update_23.html");

  script_copyright("Copyright (c) 2012 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_require_keys("Google-Chrome/Linux/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Get the version from KB
chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome Versions prior to 16.0.912.77
if(version_is_less(version:chromeVer, test_version:"16.0.912.77")){
  security_message(0);
}
