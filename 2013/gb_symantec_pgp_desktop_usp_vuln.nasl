###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_pgp_desktop_usp_vuln.nasl 7573 2017-10-26 09:18:50Z cfischer $
#
# Symantec PGP Desktop Untrusted Search Path Vulnerability
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

CPE = "cpe:/a:symantec:pgp_desktop";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803890";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 7573 $");
  script_cve_id("CVE-2010-3397");
  script_bugtraq_id(42856);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 11:18:50 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2013-09-10 13:52:56 +0530 (Tue, 10 Sep 2013)");
  script_name("Symantec PGP Desktop Untrusted Search Path Vulnerability");

  tag_summary =
"The host is installed with Symantec PGP Desktop and is prone to untrusted
search path vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaws is due to the application loading libraries (e.g. tvttsp.dll, tsp.dll)
in an insecure manner.";

  tag_impact =
"Successful exploitation will allow remote unauthenticated attacker to execute
arbitrary code and conduct DLL hijacking attacks.

Impact Level: System/Application";

  tag_affected =
"Symantec PGP Desktop 9.9.0 Build 397, 9.10.x, 10.x prior to 10.0.0 Build 2732";

  tag_solution =
"Upgrade to version 10.0.1 or later,
For updates refer to http://www.symantec.com";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41135");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2010/Sep/170");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("General");
  script_dependencies("gb_pgp_desktop_detect_win.nasl");
  script_mandatory_keys("PGPDesktop/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
rpVer = "";

## Get Symantec PGP Desktop version
if(!rpVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Check for Symantec PGP Desktop version
if(version_is_equal(version:rpVer, test_version:"9.9.0.397") ||
   version_in_range(version:rpVer, test_version:"9.10.0", test_version2:"10.0.0.2732"))
{
  security_message(0);
  exit(0);
}
