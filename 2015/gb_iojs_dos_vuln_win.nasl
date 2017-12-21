###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_iojs_dos_vuln_win.nasl 8200 2017-12-20 13:48:45Z cfischer $
#
# io.js 'V8 utf-8 decoder' Denial Of Service Vulnerability (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:iojs:io.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805944");
  script_version("$Revision: 8200 $");
  script_cve_id("CVE-2015-5380");
  script_bugtraq_id(75556);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-12-20 14:48:45 +0100 (Wed, 20 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-08-04 18:22:15 +0530 (Tue, 04 Aug 2015)");
  script_tag(name:"qod_type", value:"registry");
  script_name("io.js 'V8 utf-8 decoder' Denial Of Service Vulnerability (Windows)");

  script_tag(name: "summary" , value:"The host is installed with io.js and is
  prone to denial of service vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw is due to an error in
  'Utf8DecoderBase::WriteUtf16Slow' function in unicode-decoder.cc within Google
  V8 which does not verify that there is memory available for a UTF-16 surrogate
  pair.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to conduct denial of service attack.

  Impact Level: Application");

  script_tag(name: "affected" , value:"io.js before 1.8.3 and 2.x before 2.3.3");

  script_tag(name: "solution" , value:"Upgrade to io.js version 1.8.3 or 2.3.3 or
  later. For updates refer https://iojs.org/en/index.html");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://medium.com/node-js-javascript/important-security-upgrades-for-node-js-and-io-js-8ac14ece5852");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_iojs_detect_win.nasl");
  script_mandatory_keys("iojs/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
iojsVer = "";
report = "";

## Get version
if(!iojsVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:iojsVer, test_version:"1.8.3"))
{
  VULN =TRUE;
  Fix = "1.8.3";
}


if(version_in_range(version:iojsVer, test_version:"2.0", test_version2:"2.3.2"))
{
  VULN =TRUE;
  Fix = "2.3.3";
}

if(VULN)
{
  report = 'Installed version: ' + iojsVer + '\n' +
           'Fixed version:     ' + Fix + '\n';
  security_message(data:report);
  exit(0);
}
