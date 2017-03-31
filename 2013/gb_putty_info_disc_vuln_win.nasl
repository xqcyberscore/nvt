###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_putty_info_disc_vuln_win.nasl 3561 2016-06-20 14:43:26Z benallard $
#
# PuTTY Information Disclosure vulnerability (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "
  Impact Level: System/Application";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803880";
CPE = "cpe:/a:putty:putty";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3561 $");
  script_cve_id("CVE-2011-4607");
  script_bugtraq_id(51021);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-06-20 16:43:26 +0200 (Mon, 20 Jun 2016) $");
  script_tag(name:"creation_date", value:"2013-08-26 15:35:39 +0530 (Mon, 26 Aug 2013)");
  script_name("PuTTY Information Disclosure vulnerability (Windows)");

  tag_summary =
"The host is installed with PuTTY and is prone to information disclosure
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaw is due to improper handling of session passwords that were stored in the
memory during the keyboard-interactive authentication";

  tag_impact =
"Successful exploitation will allow local attacker to read the passwords
within the memory in clear text until the program stops running.";

  tag_affected =
"PuTTY version 0.59 before 0.62 on Windows";

  tag_solution =
"Upgrade to version 0.62 or later,
For updates refer to http://www.chiark.greenend.org.uk/~sgtatham/putty/download.html";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2011/q4/500");
  script_xref(name : "URL" , value : "http://cxsecurity.com/cveshow/CVE-2011-4607");
  script_xref(name : "URL" , value : "http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/password-not-wiped.html");
  script_summary("Check for the vulnerable version of PuTTy on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_putty_version.nasl");
  script_mandatory_keys("PuTTY/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
puttyVer = "";

## Get version from KB
puttyVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID);
if(!puttyVer){
  exit(0);
}

## Check for putty version
if(version_in_range(version:puttyVer, test_version:"0.59", test_version2:"0.61"))
{
  security_message(0);
  exit(0);
}
