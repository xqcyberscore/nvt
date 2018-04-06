###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_oct11_macosx.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Google Chrome multiple vulnerabilities - October11 (Mac OS X)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser, cause denial-of-service conditions and bypass
  the same-origin policy.
  Impact Level: System/Application";
tag_affected = "Google Chrome version prior to 14.0.835.202 on Mac OS X";
tag_insight = "Multiple flaws are due to,
  - A use-after-free error exists in text line box handling.
  - An error in the SVG text handling can be exploited to reference a stale
    font.
  - An error exists within cross-origin access handling associated with a
    window prototype.
  - Some errors exist within audio node handling related to lifetime and
    threading.
  - A use-after-free error exists in the v8 bindings.
  - An error when handling v8 hidden objects can be exploited to corrupt memory.
  - An error in the shader translator can be exploited to corrupt memory.";
tag_solution = "Upgrade to the Google Chrome 14.0.835.202 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "The host is installed with Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802256");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-10-18 15:48:35 +0200 (Tue, 18 Oct 2011)");
  script_cve_id("CVE-2011-2876", "CVE-2011-2877", "CVE-2011-2878", "CVE-2011-2879",
                "CVE-2011-2880", "CVE-2011-2881", "CVE-2011-3873");
  script_bugtraq_id(49938);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Google Chrome multiple vulnerabilities - October11 (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46308/");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.com/2011/10/stable-channel-update.html");

  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
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

## Check for Google Chrome Version less than 14.0.835.202
if(version_is_less(version:chromeVer, test_version:"14.0.835.202")){
  security_message(0);
}
