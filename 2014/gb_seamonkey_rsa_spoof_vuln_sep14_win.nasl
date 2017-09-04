#############################################################################/##
# OpenVAS Vulnerability Test
# $Id: gb_seamonkey_rsa_spoof_vuln_sep14_win.nasl 6995 2017-08-23 11:52:03Z teissa $
#
# Mozilla Seamonkey RSA Spoof Vulnerability September14 (Windows)
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:mozilla:seamonkey";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804921");
  script_version("$Revision: 6995 $");
  script_cve_id("CVE-2014-1568");
  script_bugtraq_id(70116);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-08-23 13:52:03 +0200 (Wed, 23 Aug 2017) $");
  script_tag(name:"creation_date", value:"2014-09-29 17:31:10 +0530 (Mon, 29 Sep 2014)");

  script_name("Mozilla Seamonkey RSA Spoof Vulnerability September14 (Windows)");

  script_tag(name: "summary" , value:"This host is installed with Mozilla Seamonkey
  and is prone to spoof vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Flaw exists due to improper handling of
  ASN.1 values while parsing RSA signature");

  script_tag(name: "impact" , value:"Successful exploitation will allow attackers
  to conduct spoofing attacks.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Mozilla SeaMonkey before 2.29.1 on Windows");

  script_tag(name: "solution" , value:"Upgrade to Mozilla seamonkey version 2.29.1
  or later, For updates refer to http://www.mozilla.com/en-US/seamonkey");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/61540");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1069405");
  script_xref(name:"URL", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-73.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_seamonkey_detect_win.nasl");
  script_mandatory_keys("Seamonkey/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
smVer = "";

## Get version
if(!smVer = get_app_version(cpe:CPE)){
  exit(0);
}

# Check for vulnerable version
if(version_is_less(version:smVer, test_version: "2.29.1"))
{
  security_message(0);
  exit(0);
}
