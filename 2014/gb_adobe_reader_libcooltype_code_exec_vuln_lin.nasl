###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_libcooltype_code_exec_vuln_lin.nasl 6637 2017-07-10 09:58:13Z teissa $
#
# Adobe Reader libCoolType Library Code Execution Vulnerability (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.804630");
  script_version("$Revision: 6637 $");
  script_cve_id("CVE-2001-1069");
  script_bugtraq_id(3225);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 11:58:13 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-06-05 12:35:17 +0530 (Thu, 05 Jun 2014)");
  script_name("Adobe Reader libCoolType Library Code Execution Vulnerability (Linux)");

  tag_summary =
"This host is installed with Adobe Reader and is prone to code execution
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw is due to the application creating 'AdobeFnt.lst' file with insecure
permissions.";

 tag_impact =
"Successful exploitation will allow attacker to launch a symlink attack and
execute code on the system.

Impact Level: System/Application";

  tag_affected =
"Adobe Reader version 4.0.5 and 5.0.5 on Linux.";

 tag_solution =
"Update to Adobe Reader version 5.0.6 or later. For Updates refer
http://www.adobe.com";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/7024");
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

if(readerVer  =~ "^(4|5)\.")
{
  if(version_is_equal(version:readerVer, test_version:"4.0.5")||
     version_is_equal(version:readerVer, test_version:"5.0.5"))
  {
    security_message(0);
    exit(0);
  }
}
