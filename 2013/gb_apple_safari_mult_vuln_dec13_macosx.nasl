###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_mult_vuln_dec13_macosx.nasl 6125 2017-05-15 09:03:42Z teissa $
#
# Apple Safari Multiple Vulnerabilities Dec13 (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804177";
CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6125 $");
  script_cve_id("CVE-2013-5195", "CVE-2013-5196", "CVE-2013-5197", "CVE-2013-5198",
                "CVE-2013-5199", "CVE-2013-5225", "CVE-2013-5227", "CVE-2013-5228");
  script_bugtraq_id(64356, 64353, 64358, 64359, 64361, 64360, 64355, 64362);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-05-15 11:03:42 +0200 (Mon, 15 May 2017) $");
  script_tag(name:"creation_date", value:"2013-12-24 11:34:57 +0530 (Tue, 24 Dec 2013)");
  script_name("Apple Safari Multiple Vulnerabilities Dec13 (Mac OS X)");

  tag_summary =
"This host is installed with Apple Safari and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Multiple flaws are due to,
 - Unspecified memory corruption issues within webkit.
 - An error related to origin tracking that can be exploited to autofill a form.
 - A use-after-free error exists within webkit.";

  tag_impact =
"Successful exploitation will allow local users to obtain sensitive user
information, application termination or arbitrary code execution.

Impact Level: System/Application";

  tag_affected =
"Apple Safari before version 6.1.1 and 7.x before version 7.0.1 on Mac OS X";

  tag_solution =
"Upgrade to Apple Safari version 6.1.1 or 7.0.1 or later,
For updates refer to http://www.apple.com/support";


  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT6082");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/56122");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/124511");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

# Variable Initialization
safVer = "";

## Get Apple Safari version
if(!safVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Check for Apple Safari Versions
if(version_is_less(version:safVer, test_version:"6.1.1") ||
   version_in_range(version:safVer, test_version:"7.0", test_version2:"7.0.0"))
{
  security_message(0);
  exit(0);
}
