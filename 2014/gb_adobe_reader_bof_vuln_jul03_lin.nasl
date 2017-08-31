###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_bof_vuln_jul03_lin.nasl 6724 2017-07-14 09:57:17Z teissa $
#
# Adobe Reader 'WWWLaunchNetscape' Buffer Overflow Vulnerability (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804628");
  script_version("$Revision: 6724 $");
  script_cve_id("CVE-2003-0508");
  script_bugtraq_id(8069);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-14 11:57:17 +0200 (Fri, 14 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-06-05 11:29:17 +0530 (Thu, 05 Jun 2014)");
  script_name("Adobe Reader 'WWWLaunchNetscape' Buffer Overflow Vulnerability (Linux)");

  tag_summary =
"This host is installed with Adobe Reader and is prone to buffer overflow
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw is due to a boundary error in the 'WWWLaunchNetscape' function in the
file wwwlink.api.";

 tag_impact =
"Successful exploitation will allow attacker to execute arbitrary code.

Impact Level: System/Application";

  tag_affected =
"Adobe Reader version 5.0.5, 5.0.6, 5.0.7 and probably other versions on
Linux.";

  tag_solution =
"No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/12479");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_mandatory_keys("Adobe/Reader/Linux/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Get Reader Version
if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(readerVer =~ "^(5)\.")
{
  if(version_in_range(version:readerVer, test_version:"5.0.5", test_version2:"5.0.7"))
  {
    security_message(0);
    exit(0);
  }
}
