###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_python_integer_overflow_vuln_oct14_win.nasl 8160 2017-12-18 15:33:57Z cfischer $
#
# Python Integer Overflow Vulnerability - 01 Oct14 (Windows)
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804939");
  script_version("$Revision: 8160 $");
  script_cve_id("CVE-2014-7185");
  script_bugtraq_id(70089);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-12-18 16:33:57 +0100 (Mon, 18 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-10-17 12:50:02 +0530 (Fri, 17 Oct 2014)");

  script_name("Python Integer Overflow Vulnerability - 01 Oct14 (Windows)");

  script_tag(name: "summary" , value:"The host is installed with Python
  and is prone to integer overflow vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Flaw exists as the user-supplied input is
  not properly validated when handling large buffer sizes and/or offsets.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information or cause a denial
  of service.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Python 2.7.x before version 2.7.8 on
  Windows.");

  script_tag(name: "solution" , value:"Upgrade to version 2.7.8 or later,
  For updates refer to https://www.python.org");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://bugs.python.org/issue2183");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/96193");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_python_detect_win.nasl");
  script_mandatory_keys("Python6432/Win/Installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
pythonVer = "";

## Get version
if(!pythonVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version, (2.7.7==2.7.7150)
if(version_in_range(version:pythonVer, test_version:"2.7", test_version2:"2.7.7150"))
{
  security_message(0);
  exit(0);
}
