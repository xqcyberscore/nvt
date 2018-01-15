###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zenbership_mul_sql_inj_vuln.nasl 8368 2018-01-11 07:59:53Z asteins $
#
# Zenbership 1.0.8 CMS - Multiple SQL Injection Vulnerabilities
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:castlamp:zenbership';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107222");
  script_version("$Revision: 8368 $");
  script_cve_id("CVE-2017-9759");
  script_tag(name:"last_modification", value:"$Date: 2018-01-11 08:59:53 +0100 (Thu, 11 Jan 2018) $");
  script_tag(name:"creation_date", value:"2017-06-19 11:59:56 +0200 (Mon, 19 Jun 2017)");


  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Zenbership 1.0.8 CMS - Multiple SQL Injection Vulnerabilities");

  script_tag(name: "summary", value: "Zenbership is vulnerable to multiple SQL injection vulnerabilities.");

  script_tag(name: "vuldetect", value: "Get the installed version with the help of a detection NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight", value: "The vulnerabilities are located in the error_codes, subscriptions, widget and logins parameters of the ./admin/index.php");

  script_tag(name: "impact" , value: "Attackers with privileged web-application user accounts are able to execute malicious sql commands via GET method 
request.");

  script_tag(name: "affected", value: "Zenbership - Content Management System (Web-Application) 1.0.8");

  script_tag(name: "solution", value: "No solution or patch is available as of
  11th January, 2018. Information regarding this issue will be updated once the
  solution details are available. For updates refer to https://www.zenbership.com/");

  script_xref(name: "URL" , value: "http://seclists.org/fulldisclosure/2017/Jun/16");
  script_tag(name:"solution_type", value:"NoneAvailable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("Web application abuses");

  script_dependencies("gb_zenbership_cms_detect.nasl");
  script_mandatory_keys("zenbership/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!Port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!Ver = get_app_version(cpe:CPE, port:Port))  exit(0);

if(version_is_equal(version:Ver, test_version:"108"))
{
  report =  report_fixed_ver(installed_version:Ver, fixed_version:"None Available");
  security_message(data:report, port:Port);
  exit( 0 );
}

exit ( 99 );
