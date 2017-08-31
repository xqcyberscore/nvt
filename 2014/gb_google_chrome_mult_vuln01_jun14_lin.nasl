###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln01_jun14_lin.nasl 6663 2017-07-11 09:58:05Z teissa $
#
# Google Chrome Multiple Vulnerabilities - 01 June14 (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804618");
  script_version("$Revision: 6663 $");
  script_cve_id("CVE-2014-1743", "CVE-2014-1744", "CVE-2014-1745", "CVE-2014-1746",
                "CVE-2014-1747", "CVE-2014-1748", "CVE-2014-1749", "CVE-2014-3152",
                "CVE-2014-3803");
  script_bugtraq_id(67790, 67517, 67582);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-11 11:58:05 +0200 (Tue, 11 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-06-04 10:20:11 +0530 (Wed, 04 Jun 2014)");
  script_name("Google Chrome Multiple Vulnerabilities - 01 June14 (Linux)");

  tag_summary =
"The host is installed with Google Chrome and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaws are due to,
- A use-after-free error exists in 'StyleElement::removedFromDocument' function
within core/dom/StyleElement.cpp.
- An integer overflow error exists in 'AudioInputRendererHost::OnCreateStream'
function in media/audio_input_renderer_host.cc.
- A use-after-free error exists within SVG.
- An error within media filters  in 'InMemoryUrlProtocol::Read'.
- An error in 'DocumentLoader::maybeCreateArchive' function related to a local
MHTML file.
- An error in 'ScrollView::paint' function related to scroll bars.
- Multiple unspecified errors exist.
- An integer overflow error in 'LCodeGen::PrepareKeyedOperand' function in
arm/lithium-codegen-arm.cc within v8.
- Some error in speech API within Blink.";

  tag_impact =
"Successful exploitation will allow remote attackers to conduct a denial of
service, inject arbitrary web script or HTML, spoof the UI, enable microphone
access and obtain speech-recognition text and possibly have other unspecified
impact.

Impact Level: System/Application";

  tag_affected =
"Google Chrome version prior to 35.0.1916.114 on Linux.";

  tag_solution =
"Upgrade to Google Chrome 35.0.1916.114 or later,
For updates refer to http://www.google.com/chrome";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2014/05/stable-channel-update_20.html");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
chromeVer = "";

## Get version
if(!chromeVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:chromeVer, test_version:"35.0.1916.114"))
{
  security_message(0);
  exit(0);
}
