###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_quick_heal_stack_bof_vuln.nasl 2013-12-30 17:01:32Z dec$
#
# Quick Heal Antivirus Pro 'pepoly.dll' Stack Buffer Overflow Vulnerability
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

CPE = "cpe:/a:quickheal:antivirus_pro";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804181");
  script_version("$Revision: 8160 $");
  script_cve_id("CVE-2013-6767");
  script_bugtraq_id(64402);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-18 16:33:57 +0100 (Mon, 18 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-12-30 20:51:30 +0530 (Mon, 30 Dec 2013)");
  script_name("Quick Heal Antivirus Pro 'pepoly.dll' Stack Buffer Overflow Vulnerability");

  tag_summary =
"This host is installed with Quick Heal Antivirus Pro and is prone to stack
buffer overflow vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw is due to improper bounds checking by the 'pepoly.dll' module.";

  tag_impact =
"Successful exploitation will allow a local attacker to cause a stack-based
buffer overflow, resulting in a denial of service or execution of arbitrary
code.

Impact Level: System/Application";

  tag_affected =
"Quick Heal AntiVirus Pro version 7.0.0.1 and probably other versions.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/30374");
  script_xref(name : "URL" , value : "http://www.vulnerability-lab.com/get_content.php?id=1171");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_quick_heal_av_detect.nasl");
  script_mandatory_keys("QuickHeal/Antivirus6432/Pro/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
qhVer = "";

## Get version
if(!qhVer = get_app_version(cpe:CPE)){
  exit(0);
}

# Check for vulnerable version
if(version_is_equal(version:qhVer, test_version:"7.0.0.1"))
{
  security_message(0);
  exit(0);
}
