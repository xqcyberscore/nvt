###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_esr_spoofing_vuln_jan16_macosx.nasl 5598 2017-03-17 10:00:43Z teissa $
#
# Mozilla ESR Spoofing Vulnerability - Jan16 (Mac OS X)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806955");
  script_version("$Revision: 5598 $");
  script_cve_id("CVE-2015-7575");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-17 11:00:43 +0100 (Fri, 17 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-01-14 10:52:36 +0530 (Thu, 14 Jan 2016)");
  script_name("Mozilla ESR Spoofing Vulnerability - Jan16 (Mac OS X)");

  script_tag(name: "summary" , value:"This host is installed with Mozilla
  Firefox ESR and is prone to spoofing vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to Server Key Exchange messages
  in TLS 1.2 Handshake Protocol traffic does not reject MD5 signatures.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to spoof servers by triggering a collision.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Mozilla Firefox ESR version from 38.x before 38.5.2 on
  Mac OS X.");

  script_tag(name: "solution" , value:"Upgrade to Mozilla Firefox ESR version 38.5.2
  or later, For updates refer to http://www.mozilla.com/en-US/firefox/all.html");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-150/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
ffVer = "";

## Get version
if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

# Check for vulnerable version
if(version_in_range(version:ffVer, test_version:"38.0", test_version2:"38.5.1"))
{
  report = 'Installed version: ' + ffVer + '\n' +
           'Fixed version:     ' + "38.5.2" + '\n';
  security_message(data:report);
  exit(0);
}

