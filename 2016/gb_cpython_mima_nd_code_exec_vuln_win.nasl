###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cpython_mima_nd_code_exec_vuln_win.nasl 7545 2017-10-24 11:45:30Z cfischer $
#
# Cpython Man in Middle Attack and Code Execution Vulnerabilities (Windows)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809216");
  script_version("$Revision: 7545 $");
  script_cve_id("CVE-2016-5636", "CVE-2016-0772");
  script_bugtraq_id(91247, 91225);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 13:45:30 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"creation_date", value:"2016-09-12 12:56:46 +0530 (Mon, 12 Sep 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Cpython Man in Middle Attack and Code Execution Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"This host is running Cpython and is
  prone to man in middle attack and arbitrary code execution Vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The multiple flaws exist due to the smtplib 
  library in CPython does not return an error when StartTLS fails and integer 
  overflow error in the 'get_data' function in 'zipimport.c' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  man-in-the-middle attackers to bypass the TLS protections and remote attackers
  to cause buffer overflow.

  Impact Level: Application");

  script_tag(name:"affected", value:"Cpython before 2.7.12, 3.x before 3.4.5,
  and 3.5.x before 3.5.2 on Windows.");

  script_tag(name:"solution", value:"Upgrade to version Cpython 2.7.12, or
  3.4.5, or 3.5.2 or later. For updates refer to https://hg.python.org/cpython");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://hg.python.org/cpython/rev/d590114c2394");
  script_xref(name : "URL" , value : "https://bugs.python.org/issue26171");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_Python_detection.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("pyVer/installed","Host/runs_windows");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
pythonPort = "";
pythonVer = "";

## Get HTTP Port
if(!pythonPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get Version
if(!pythonVer = get_app_version(cpe:CPE, port:pythonPort)){
  exit(0);
}

## Check for version before 2.7.12
if(version_is_less(version:pythonVer, test_version:"2.7.12"))
{
  fix = '2.7.12';
  VULN = TRUE;
}

## Check for version before 3.4.5
else if(pythonVer =~ "^(3\.)")
{
  if(version_in_range(version:pythonVer, test_version:"3.0", test_version2:"3.4.4"))
  {
    fix = '3.4.5';
    VULN = TRUE;
  }
}

## Check for version 3.5.x before 3.5.2
else if(pythonVer =~ "^(3\.5)")
{
  if(version_in_range(version:pythonVer, test_version:"3.5.0", test_version2:"3.5.1"))
  {
    fix = '3.5.2';
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:pythonVer, fixed_version:fix);
  security_message(data:report, port:pythonPort);
  exit(0);
}
