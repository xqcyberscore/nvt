###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_bof_vuln_sep09_win.nasl 8210 2017-12-21 10:26:31Z cfischer $
#
# Adobe Reader Buffer Overflow Vulnerability Sep09 (Windows)
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804365";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 8210 $");
  script_cve_id("CVE-1999-1576");
  script_bugtraq_id(666);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 11:26:31 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-04-07 18:42:55 +0530 (Mon, 07 Apr 2014)");
  script_name("Adobe Reader Buffer Overflow Vulnerability Sep09 (Windows)");

  tag_summary =
"This host is installed with Adobe Reader and is prone to buffer overflow
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaw is due to various boundary condition errors in acrobat activeX control.";

  tag_impact =
"Successful exploitation will allow attackers to execute arbitrary code on the
user's system.

Impact Level: System/Application";

  tag_affected =
"Adobe Reader version 4.0 on Windows.";

  tag_solution =
"Upgrade to Adobe Reader version 5.0.5 or later.
For updates refer to http://get.adobe.com/reader";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/25919");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/3318");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/19514");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/1999-q3/1061.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Acrobat/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
readerVer = "";


## Get version
if(!readerVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

if(readerVer && readerVer =~ "^4")
{
  ## Check Adobe Reader vulnerable versions
  if(version_is_equal(version:readerVer, test_version:"4.0"))
  {
    security_message(0);
    exit(0);
  }
}
