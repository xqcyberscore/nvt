###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_openoffice_mult_vuln01_may15_macosx.nasl 6141 2017-05-17 09:03:37Z teissa $
#
# Apache OpenOffice Multiple Vulnerabilities -01 May15 (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:openoffice:openoffice.org";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805610");
  script_version("$Revision: 6141 $");
  script_cve_id("CVE-2014-3575", "CVE-2014-3524");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-05-17 11:03:37 +0200 (Wed, 17 May 2017) $");
  script_tag(name:"creation_date", value:"2015-06-01 12:23:19 +0530 (Mon, 01 Jun 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Apache OpenOffice Multiple Vulnerabilities -01 May15 (Mac OS X)");

  script_tag(name: "summary" , value:"The host is installed with Apache
  OpenOffice and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws are due to,
  - An error in application due to the way the it generates OLE previews when
    handling a specially crafted document that is distributed to other parties.
  - An error in application that is triggered when handling specially
    crafted Calc spreadsheets.");

  script_tag(name: "impact" , value:"Successful exploitation will allow a
  context-dependent attacker to gain access to potentially sensitive information
  and to execute arbitrary commands.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Apache OpenOffice before 4.1.1 on Mac OS X.");

  script_tag(name: "solution" , value:"Upgrade to Apache OpenOffice version
  4.1.1 or later, For updates refer to http://www.openoffice.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1030755");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1030754");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_openoffice_detect_macosx.nasl");
  script_mandatory_keys("OpenOffice/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
openoffcVer = "";
report = "";

## Get version
## CPE is changed for newer versions of OpenOffice
if(!openoffcVer = get_app_version(cpe:CPE)){
  exit(0);
}
## Grep for vulnerable version
if(version_is_less(version:openoffcVer, test_version:"4.1.1"))
{
  report = 'Installed version: ' + openoffcVer + '\n' +
           'Fixed version:     ' + "4.1.1" + '\n';
  security_message(data:report);
  exit(0);
}
