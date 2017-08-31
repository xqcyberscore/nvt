###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln01_oct14_lin.nasl 6715 2017-07-13 09:57:40Z teissa $
#
# Google Chrome Multiple Vulnerabilities - 01 Oct14 (Linux)
#
# Authors:
# Deepmala <kdeepmala@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804938");
  script_version("$Revision: 6715 $");
  script_cve_id("CVE-2014-3200", "CVE-2014-3199", "CVE-2014-3198", "CVE-2014-3197",
                "CVE-2014-3195", "CVE-2014-3194", "CVE-2014-3193", "CVE-2014-3192",
                "CVE-2014-3191", "CVE-2014-3190", "CVE-2014-3189", "CVE-2014-3188",
                "CVE-2014-7967");
  script_bugtraq_id(70273, 70262, 70587);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-13 11:57:40 +0200 (Thu, 13 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-10-16 16:48:48 +0530 (Thu, 16 Oct 2014)");

  script_name("Google Chrome Multiple Vulnerabilities - 01 Oct14 (Linux)");

  script_tag(name: "summary" , value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws exist due to,
  - Some errors related to V8 and IPC.
  - An out-of-bound read access error in PDFium.
  - Multiple use-after-free errors in Events, Rendering, DOM,and Web Workers.
  - A type confusion error in Session Management.
  - An information leak error in the V8 JavaScript engine and the XSS Auditor.
  - An error within V8 bindings.
  - Other multiple unspecified errors.");

  script_tag(name: "impact" , value:"Successful exploitation will allow attackers
  to disclose potentially sensitive information, bypass certain security
  restrictions, conduct denial-of-service attacks, compromise a vulnerable system
  or possibly have unspecified other impact.

  Impact Level: Application/System");

  script_tag(name: "affected" , value:"Google Chrome prior to version 38.0.2125.101
  on Linux.");

  script_tag(name: "solution" , value:"Upgrade to Google Chrome 38.0.2125.101 or later,
  For updates refer to http://www.google.com/chrome");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/61755");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2014/10/stable-channel-update.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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
if(version_is_less(version:chromeVer, test_version:"38.0.2125.101"))
{
  security_message(0);
  exit(0);
}
