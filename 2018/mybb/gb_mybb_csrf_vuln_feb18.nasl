##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mybb_csrf_vuln_feb18.nasl 8952 2018-02-26 11:51:34Z santu $
#
# MyBB Cross Site Request Forgery Vulnerability
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:mybb:mybb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812807");
  script_version("$Revision: 8952 $");
  script_cve_id("CVE-2018-7305");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-02-26 12:51:34 +0100 (Mon, 26 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-02-22 15:03:22 +0530 (Tue, 22 Feb 2018)");
  script_name("MyBB Cross Site Request Forgery Vulnerability");
  
  script_tag(name:"summary", value:"The host is installed with MyBB and is
  prone to cross site request forgery vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of the detect NVT and check if the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to MyBB not checking
  for a valid CSRF token.");

  script_tag(name:"impact", value:"Successfully exploitation will allows an
  attackers to delete arbitrary user accounts.

  Impact Level: Application");

  script_tag(name:"affected", value:"MyBB version 1.8.14");

  script_tag(name:"solution", value:"No solution or patch is available as of
  22nd February, 2018. Information regarding this issue will be updated once
  solution details are available. For updates refer to https://mybb.com");
  
  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"remote-banner");
  script_xref(name:"URL", value:"https://websecnerd.blogspot.in/2018/02/mybb-forum-1_21.html");
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("sw_mybb_detect.nasl");
  script_mandatory_keys("MyBB/installed");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

infos = get_app_version_and_location(cpe:CPE, port: port, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

if(vers == "1.8.14")
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"None Available", install_path:path);
  security_message(data:report, port: port);
  exit(0);
}
exit(0);
