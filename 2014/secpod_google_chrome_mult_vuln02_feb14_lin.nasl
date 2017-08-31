###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_mult_vuln02_feb14_lin.nasl 6715 2017-07-13 09:57:40Z teissa $
#
# Google Chrome Multiple Vulnerabilities-02 Feb2014 (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 SecPod, http://www.secpod.com
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.903516";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6715 $");
  script_cve_id("CVE-2013-6653", "CVE-2013-6654", "CVE-2013-6655", "CVE-2013-6656",
                "CVE-2013-6657", "CVE-2013-6658", "CVE-2013-6659", "CVE-2013-6660",
                "CVE-2013-6661");
  script_bugtraq_id(65699);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-13 11:57:40 +0200 (Thu, 13 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-02-26 11:37:10 +0530 (Wed, 26 Feb 2014)");
  script_name("Google Chrome Multiple Vulnerabilities-02 Feb2014 (Linux)");

  tag_summary =
"The host is installed with Google Chrome and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Multiple flaws are due to,
- A use-after-free error related to web contents can be exploited to cause
  memory corruption.
- An unspecified error exists in 'SVGAnimateElement::calculateAnimatedValue'
  function related to type casting in SVG.
- A use-after-free error related to layout can be exploited to cause memory
  corruption.
- An error in XSS auditor 'XSSAuditor::init' function can be exploited to
  disclose certain information.
- Another error in XSS auditor can be exploited to disclose certain information.
- Another use-after-free error related to layout can be exploited to cause
  memory corruption
- An unspecified error exists in 'SSLClientSocketNSS::Core::OwnAuthCertHandler'
  function related to certificates validation in TLS handshake.
- An error in drag and drop can be exploited to disclose unspecified
  information.
- Some unspecified errors exist. No further information is currently available.";

  tag_impact =
"Successful exploitation will allow remote attackers to conduct denial of
service, execution of arbitrary code and unspecified other impacts.

Impact Level: System/Application";

  tag_affected =
"Google Chrome version prior to 33.0.1750.117 on Linux";

  tag_solution =
"Upgrade to version 33.0.1750.117 or later,
For updates refer to http://www.google.com/chrome";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/57028");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1029813");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2014/02/stable-channel-update_20.html");
  script_copyright("Copyright (C) 2014 SecPod");
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
if(!chromeVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:chromeVer, test_version:"33.0.1750.117"))
{
  security_message(0);
  exit(0);
}
