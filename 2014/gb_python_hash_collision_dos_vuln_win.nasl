# OpenVAS Vulnerability Test
# $Id: gb_python_hash_collision_dos_vuln_win.nasl 8160 2017-12-18 15:33:57Z cfischer $
#
# Python 'Hash Collision' Denial of Service Vulnerability (Windows)
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

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804632");
  script_version("$Revision: 8160 $");
  script_cve_id("CVE-2013-7040");
  script_bugtraq_id(64194);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-12-18 16:33:57 +0100 (Mon, 18 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-06-09 14:43:46 +0530 (Mon, 09 Jun 2014)");
  script_name("Python 'Hash Collision' Denial of Service Vulnerability (Windows)");

  tag_summary =
"This host is installed with Python and is prone to denial of service
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaw is due to an error within a hash generation function when hashing form
posts and updating a hash table.";

  tag_impact =
"Successful exploitation will allow a remote attacker to cause a hash collision
resulting in a denial of service.

Impact Level: Application";

  tag_affected =
"Python version 2.7 before 3.4";

  tag_solution =
"Upgrade to Python version 3.4 or later. 
For updates refer to www.python.org/download";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/55955");
  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2013/q4/439");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2013/12/09/3");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_python_detect_win.nasl");
  script_mandatory_keys("Python6432/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("global_settings.inc");

## Variable Initialization
pyVer = "";

## Get version
if(!pyVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Check for Python version 3.3.5=3.3.5150
if(version_in_range(version:pyVer, test_version:"2.7", test_version2:"3.3.5150"))
{
  security_message(0);
  exit(0);
}
