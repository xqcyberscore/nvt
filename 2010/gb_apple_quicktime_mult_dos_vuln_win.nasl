###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_quicktime_mult_dos_vuln_win.nasl 8168 2017-12-19 07:30:15Z teissa $
#
# Apple QuickTime Multiple Denial Of Service Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will let attacker to cause an unexpected application
  termination or arbitrary code execution.
  Impact Level: Application";
tag_affected = "Apple QuickTime before 7.6.6 on Windows.";
tag_insight = "Multiple flaws are due to:
  - An heap buffer overflow in the handling of PICT images.
  - A memory corruption issue in the handling of BMP images.
  - An integer overflow in the handling of 'PICT' images.
  - A memory corruption the handling of color tables in movie files.";
tag_solution = "Upgrade to Apple QuickTime version 7.6.6 or later,
  http://www.apple.com/quicktime/download/";
tag_summary = "The host is installed with Apple QuickTime and is prone to
   multiple Denial Of Service vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800494");
  script_version("$Revision: 8168 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 08:30:15 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-04-06 08:47:09 +0200 (Tue, 06 Apr 2010)");
  script_cve_id("CVE-2010-0527", "CVE-2010-0529", "CVE-2010-0528", "CVE-2010-0536");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Apple QuickTime Multiple Denial Of Service Vulnerabilities (Windows)");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/392440.php");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Mar/1023790.html");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2010//Mar/msg00002.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_require_keys("QuickTime/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

qtVer = get_kb_item("QuickTime/Win/Ver");
if(!qtVer){
  exit(0);
}

# QuickTime version < 7.6.6
if(version_is_less(version:qtVer, test_version:"7.6.6")){
  security_message(0);
}
