###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_iprint_client_unspecified_rce_vuln_win.nasl 8201 2017-12-20 14:28:50Z cfischer $
#
# Novell iPrint Client Unspecified Remote Code Execution Vulnerability (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:novell:iprint";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810591");
  script_version("$Revision: 8201 $");
  script_cve_id("CVE-2012-0411");
  script_bugtraq_id(57037);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-20 15:28:50 +0100 (Wed, 20 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-03-14 13:19:08 +0530 (Tue, 14 Mar 2017)");
  script_name("Novell iPrint Client Unspecified Remote Code Execution Vulnerability (Windows)");

  script_tag(name: "summary" , value:"This host is running Novell iPrint Client 
  and is prone to an unspecified remote code execution vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help 
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw is due to an unspecified 
  error in Novell iPrint Client.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to execute arbitrary code via an op-client-interface-version action. 

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Novell iPrint Client versions before 5.82 on Windows");

  script_tag(name: "solution" , value:"Upgrade to Novell iPrint Client 5.82 or later,
  For updates refer to https://www.novell.com");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "https://vulners.com/cve/CVE-2012-0411");
  script_xref(name : "URL" , value : "https://www.novell.com/support/kb/doc.php?id=7008708");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_novell_prdts_detect_win.nasl");
  script_mandatory_keys("Novell/iPrint/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
niVer  = "";
report = "";

##Fetch ibmdb2 version
if(!niVer = get_app_version(cpe:CPE)){
  exit(0);
}

##Check for Novell iPrint Client vulnerable versions
if(version_is_less(version:niVer, test_version:"5.82"))
{
  report = report_fixed_ver(installed_version:niVer, fixed_version:"5.82");
  security_message(data:report);
  exit(0);
}
