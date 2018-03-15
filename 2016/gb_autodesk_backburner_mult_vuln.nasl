###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_autodesk_backburner_mult_vuln.nasl 9104 2018-03-14 17:05:40Z cfischer $
#
# Autodesk Backburner Multiple Vulnerabilities
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:autodesk:autodesk_backburner";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808172");
  script_version("$Revision: 9104 $");
  script_cve_id("CVE-2016-2344");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-03-14 18:05:40 +0100 (Wed, 14 Mar 2018) $");
  script_tag(name:"creation_date", value:"2016-06-21 18:29:15 +0530 (Tue, 21 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Autodesk Backburner Multiple Vulnerabilities");

  script_tag(name: "summary" , value:"This host is installed with Autodesk
  Backburner and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight", value:"Multiple flaw exists due to a stack-based
  buffer overflow in manager.exe in Backburner Manager in Autodesk Backburner.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to execute arbitrary code or cause a denial of service.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Autodesk Backburner version
  2016.0.0.2150 and earlier.");

  script_tag(name: "solution" , value:"As a workaround Restrict access to the
  Backburner manager.exe service to trusted users and networks.
  For updates refer to https://knowledge.autodesk.com.");

  script_tag(name:"solution_type", value:"Workaround");

  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/732760");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_autodesk_backburner_detect.nasl");
  script_mandatory_keys("Autodesk/Backburner/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!back_port = get_app_port(cpe:CPE)){
 exit(0);
}

if(!backVer = get_app_version(cpe:CPE, port:back_port)){
  exit(0);
}

if(version_is_less_equal(version:backVer, test_version:"2016.0.0.2150"))
{
  report = report_fixed_ver(installed_version:backVer, fixed_version:"Workaround");
  security_message(data:report, port:back_port);
  exit(0);
}
