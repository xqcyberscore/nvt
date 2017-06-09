###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_measuresoft_scadapro_svr_dll_code_exe_vuln.nasl 6104 2017-05-11 09:03:48Z teissa $
#
# Measuresoft ScadaPro Server DLL Code Execution Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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

CPE = "cpe:/a:measuresoft:scadapro_server";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803949";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6104 $");
  script_cve_id("CVE-2012-1824");
  script_bugtraq_id(53681);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-05-11 11:03:48 +0200 (Thu, 11 May 2017) $");
  script_tag(name:"creation_date", value:"2013-10-03 12:30:46 +0530 (Thu, 03 Oct 2013)");
  script_name("Measuresoft ScadaPro Server DLL Code Execution Vulnerability");

tag_summary =
"The host is installed with Measuresoft ScadaPro Server and is prone to code
execution vulnerability.";

tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

tag_insight =
"A flaw exists in the application, which does not directly specify the fully
qualified path to a dynamic-linked library.";

tag_impact =
"Successful exploitation will allow attackers to execute arbitrary code on the
system via a specially-crafted library.

Impact Level: System/Application";

tag_affected =
"Measuresoft ScadaPro Server before 4.0.0";

tag_solution =
"Upgrade to version 4.0.0 or later,
For updates refer to http://www.measuresoft.com/download/current_release.aspx";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/75860");
  script_xref(name : "URL" , value : "http://www.us-cert.gov/control_systems/pdf/ICSA-12-145-01.pdf");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_measuresoft_scadapro_server_detect.nasl");
  script_mandatory_keys("ScadaProServer/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

scadaprosvrVer = "";

## Get the version
if(!scadaprosvrVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Check for WinSCP version
if(version_is_less(version:scadaprosvrVer, test_version:"4.0.0"))
{
  security_message(0);
  exit(0);
}
