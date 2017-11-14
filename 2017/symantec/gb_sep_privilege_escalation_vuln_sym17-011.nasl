###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sep_privilege_escalation_vuln_sym17-011.nasl 7736 2017-11-10 13:58:57Z cfischer $
#
# Symantec Endpoint Protection Privilege Escalation Vulnerability (SYM17-011)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:symantec:endpoint_protection";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812068");
  script_version("$Revision: 7736 $");
  script_cve_id("CVE-2017-13681");
  script_bugtraq_id(101504);
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-11-10 14:58:57 +0100 (Fri, 10 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-08 11:56:13 +0530 (Wed, 08 Nov 2017)");
  script_name("Symantec Endpoint Protection Privilege Escalation Vulnerability (SYM17-011)");
                
  script_tag(name: "summary" , value:"This host is installed with Symantec
  Endpoint Protection and is prone to privilege escalation vulnerability.");

  script_tag(name: "vuldetect" , value: "Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value: "The flaw exists due to unspecified error
  within the application.");

  script_tag(name: "impact" , value: "Successful exploitation will allow local
  attacker to gain elevated privileges on the affected system.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Symantec Endpoint Protection prior to SEP
  12.1 RU6 MP9");

  script_tag(name: "solution" , value:"Upgrade to SEP 12.1 RU6 MP9 or later. 
  For updates refer to, https://www.symantec.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name: "URL" , value : "https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20171106_00");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Symantec/Endpoint/Protection");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

sepVer= "";
infos = "";
sepPath = "";

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
sepVer = infos['version'];
sepPath = infos['location'];

## Check for vulnerable version, 12.1 RU 6 MP8 == 12.1.7266.6800 (https://symwisedownload.symantec.com//resources/sites/SYMWISE/content/live/DOCUMENTATION/10000/DOC10664/en_US/Release_Notes_SEP12.1.6.9.pdf?__gda__=1510259634_5c951540545a10df49506b622a48bd42)
if(version_is_less_equal(version:sepVer, test_version:"12.1.7266.6800"))
{
  report = report_fixed_ver(installed_version:sepVer, fixed_version:"SEP 12.1 RU6 MP9", install_path:sepPath);
  security_message(data:report);
  exit(0);
}
exit(0);
