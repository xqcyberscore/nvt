###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_mult_vuln_macosx_mar12.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Google Chrome Multiple Vulnerabilities (MAC OS X) - Mar 12
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code,
  cause a denial of service.
  Impact Level: System/Application";
tag_affected = "Google Chrome version prior to 17.0.963.83 on MAC OS X";
tag_insight = "The flaws are due to
  - Not properly restrict the extension web request API.
  - Memory corruption in WebGL canvas handling.
  - Use-after-free in block splitting.
  - An error in WebUI privilege implementation which fails to properly perform
    isolation.
  - Prompt in the browser native UI for unpacked extension installation.
  - Cross-origin violation with magic iframe.
  - An invalid read error exists within v8.
  - A use-after-free error exists when handling CSS cross-fade.
  - A use-after-free error exists when handling the first letter.
  - An error exists in the bundled version of libpng.";
tag_solution = "Upgrade to Google Chrome version 17.0.963.83 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "This host is installed with Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903006");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2011-3049", "CVE-2011-3052", "CVE-2011-3053", "CVE-2011-3054",
                "CVE-2011-3055", "CVE-2011-3056", "CVE-2011-3057", "CVE-2011-3051",
                "CVE-2011-3050", "CVE-2011-3045");
  script_bugtraq_id(52674);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-03-26 16:40:40 +0530 (Mon, 26 Mar 2012)");
  script_name("Google Chrome Multiple Vulnerabilities (MAC OS X) - Mar 12");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48512/");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1026841");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2012/03/stable-channel-update_21.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
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

## Variable Initialization
chromeVer = "";

## Get the version from KB
chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome version < 17.0.963.83
if(version_is_less(version:chromeVer, test_version:"17.0.963.83")){
  security_message(0);
}
