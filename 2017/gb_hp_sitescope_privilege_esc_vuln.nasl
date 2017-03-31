###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_sitescope_privilege_esc_vuln.nasl 5301 2017-02-15 09:16:50Z antu123 $
#
# HP SiteScope Remote Privilege Escalation Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:hp:sitescope";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807398");
  script_version("$Revision: 5301 $");
  script_cve_id("CVE-2015-2120");
  script_bugtraq_id(74801);
  script_tag(name:"cvss_base", value:"8.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:P/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-02-15 10:16:50 +0100 (Wed, 15 Feb 2017) $");
  script_tag(name:"creation_date", value:"2017-02-14 15:29:33 +0530 (Tue, 14 Feb 2017)");
  script_name("HP SiteScope Remote Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"This host is running HP SiteScope and is
  prone to remote privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version of HP SiteScope
  with the help of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The specific flaw exists within the
  'Log Analysis Tool', which does not validate or restrict the log path allowing the
  users to read the 'users.config' file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to escalate privileges from the user to administrator role.

  Impact Level: Application");

  script_tag(name:"affected", value:"HP SiteScope versions 11.1x before 11.13,
  11.2x before 11.24.391, and 11.3x before 11.30.521");

  script_tag(name:"solution", value:"Upgrade to SiteScope 11.13, or 11.24.391,
  or 11.30.521, or later,
  http://www8.hp.com/us/en/software-solutions/sitescope-application-monitoring/index.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-15-239");
  script_xref(name : "URL" , value : "https://h20566.www2.hp.com/hpsc/doc/public/display?docId=emr_na-c04688784");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hp_sitescope_detect.nasl");
  script_mandatory_keys("hp/sitescope/installed");
  script_require_ports("Services/www", 8080);
  exit(0);
}

##
## Code starts here
##

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
http_port = "";
hpVer= "";

## Get HTTP Port
if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

# Get Version
if(!hpVer = get_app_version(cpe:CPE, port:http_port)){
  exit(0);
}

if(version_in_range(version:hpVer, test_version:"11.10", test_version2:"11.12"))
{
  fix = "SiteScop 11.13";
  VULN = TRUE;
}

else if(version_in_range(version:hpVer, test_version:"11.20", test_version2:"11.24.390"))
{
  fix = "SiteScop 11.24.391";
  VULN = TRUE;
}

else if(version_in_range(version:hpVer, test_version:"11.30", test_version2:"11.30.520"))
{
  fix = "SiteScop 11.30.521";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:hpVer, fixed_version:fix);
  security_message(data:report, port:http_port);
  exit(0);
}
