##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avast_ep_sanbox_escape_sec_bypass_vuln.nasl 7915 2017-11-27 10:32:14Z teissa $
#
# Avast Endpoint Protection Sandbox Escape Security Bypass Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

CPE = "cpe:/a:avast:endpoint_protection";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810212");
  script_version("$Revision: 7915 $");
  script_cve_id("CVE-2016-4025");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-11-27 11:32:14 +0100 (Mon, 27 Nov 2017) $");
  script_tag(name:"creation_date", value:"2016-11-24 14:26:59 +0530 (Thu, 24 Nov 2016)");
  script_name("Avast Endpoint Protection Sandbox Escape Security Bypass Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Avast Endpoint
  Protection and is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to a design flaw in the
  Avast DeepScreen feature.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to escape from a fully sandboxed process, furthermore attacker can also freely
  modify or infect or encrypt any existing file in the case of a ransomware attack.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Avast Endpoint Protection version 8.x
  through 8.0.1609");

  script_tag(name:"solution", value:"No solution or patch was made available for at least one year since disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "https://labs.nettitude.com/blog/escaping-avast-sandbox-using-single-ioctl-cve-2016-4025");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_avast_endpoint_protection_detect.nasl");
  script_mandatory_keys("Avast/Endpoint-Protection/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
avastVer = "";

## Get version
if(!avastVer = get_app_version(cpe:CPE)){
  exit(0);
}
if(avastVer =~ "^(8)")
{
  if(version_in_range(version:avastVer, test_version:"8.0", test_version2:"8.0.1609"))
  {
    report = report_fixed_ver(installed_version:avastVer, fixed_version:"WillNotFix");
    security_message(data:report);
    exit(0);
  }
}
