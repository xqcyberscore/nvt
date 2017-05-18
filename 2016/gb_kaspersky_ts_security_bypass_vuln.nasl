###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kaspersky_ts_security_bypass_vuln.nasl 5675 2017-03-22 10:00:52Z teissa $
#
# Kaspersky Total Security Security Bypass Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:kaspersky:total_security_2015";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806854");
  script_version("$Revision: 5675 $");
  script_cve_id("CVE-2015-8579");
  script_bugtraq_id(78815);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-22 11:00:52 +0100 (Wed, 22 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-02-04 10:20:32 +0530 (Thu, 04 Feb 2016)");
  script_name("Kaspersky Total Security Security Bypass Vulnerability");

  script_tag(name: "summary" , value:"The host is installed with Kaspersky Total
  security and is prone to security bypass vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw is due to 
  allocation of memory with Read, Write, Execute (RWX) permissions at predictable
  addresses when protecting user-mode processes.");

  script_tag(name: "impact" , value:"Successful exploitation would allow remote
  attackers to bypass the DEP and ASLR protection mechanisms via unspecified vectors.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Kaspersky Total Security version 15.0.2.361");

  script_tag(name: "solution" , value:"Upgrade to latest version of Kaspersky Total
  Security from the below link.
  For Updates refer to http://usa.kaspersky.com/downloads/");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "http://blog.ensilo.com/the-av-vulnerability-that-bypasses-mitigations");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_kaspersky_total_security_detect.nasl");
  script_mandatory_keys("Kaspersky/TotalSecurity/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
kasVer = "";

## Get version
if(!kasVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_equal(version:kasVer, test_version:"15.0.2.361"))
{
  report = report_fixed_ver(installed_version:kasVer, fixed_version:"Upgrade to latest version");
  security_message(data:report);
  exit(0);
}
