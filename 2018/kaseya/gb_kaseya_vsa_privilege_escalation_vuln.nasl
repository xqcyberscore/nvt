###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kaseya_vsa_privilege_escalation_vuln.nasl 10041 2018-05-31 12:51:28Z santu $
#
# Kaseya Virtual System Administrator Agent Local Privilege Escalation Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:kaseya:virtual_system_administrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813382");
  script_version("$Revision: 10041 $");
  script_cve_id("CVE-2017-12410");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-05-31 14:51:28 +0200 (Thu, 31 May 2018) $");
  script_tag(name:"creation_date", value:"2018-05-30 11:18:44 +0530 (Wed, 30 May 2018)");
  script_name("Kaseya Virtual System Administrator Agent Local Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"This host is running Kaseya 
  Virtual System Administrator agent and is prone to local privilege escalation 
  vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of the detect NVT and check if the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to a Time of Check & 
  Time of Use (TOCTOU) issue when VSA agent performs verification if the
  files were modified before running the executables.");

  script_tag(name: "impact" , value:"Successful exploitation will allow an
  attacker to run arbitrary executables with 'NT AUTHORITY\SYSTEM' privileges.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Kaseya Virtual System Administrator 
  agent 9.4.0.36 and earlier.");

  script_tag(name: "solution" , value:"Upgrade to Kaseya Virtual System 
  Administrator version 9.4.0.37 or 9.5 or later. 
  For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://www.securityfocus.com/archive/1/archive/1/541884/100/0/threaded");
  script_xref(name:"URL", value:"https://helpdesk.kaseya.com/hc/en-gb/articles/360002367172-CVE-2017-12410-TOCTOU-Flaw-in-the-VSA-s-Agent-");
  script_xref(name:"URL", value:"https://www.kaseya.com/products/vsa");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_kaseya_vsa_detect.nasl");
  script_mandatory_keys("kaseya_vsa/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vsPort = get_app_port(cpe:CPE)){
  exit(0);
}

infos = get_app_version_and_location( cpe:CPE, port:vsPort, exit_no_version:TRUE );
vsVer = infos['version'];
vsPath = infos['location'];

if(version_is_less(version:vsVer, test_version:"9.4.0.37"))
{
  report = report_fixed_ver(installed_version:vsVer, fixed_version: "9.4.0.37 or 9.5", install_path:vsPath);
  security_message(port:vsPort, data: report);
  exit(0);
}
exit(0);
