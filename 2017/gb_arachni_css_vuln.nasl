###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_arachni_css_vuln.nasl 6363 2017-06-16 16:32:17Z teissa $
#
# Arachni v1.5-0.5.11 - Cross Site Scripting Vulnerability
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

CPE = "cpe:/a:arachni:arachni";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107221");
  script_version("$Revision: 6363 $");
  script_tag(name:"last_modification", value:"$Date: 2017-06-16 18:32:17 +0200 (Fri, 16 Jun 2017) $");
  script_tag(name:"creation_date", value:"2017-06-15 12:26:25 +0200 (Thu, 15 Jun 2017)");

  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Arachni v1.5-0.5.11 - Cross Site Scripting Vulnerability");

  script_tag(name: "summary", value: "Arachni is vulnerable to Cross Site Scripting Vulnerability.");

  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight", value: "The Target URL field which is available when configuring a scan is vulnerable to cross site scripting. As scans can be shared and viewed by other users including the admin account, it is possible to execute the cross site scripting under another users context.");

  script_tag(name: "impact" , value: "The vulnerability allows remote attackers to inject own malicious script codes on the application-side of the vulnerable service.");

  script_tag(name: "affected", value: "Arachni Version 1.5-0.5.11");

  script_tag(name: "solution", value: "No solution or patch is available as of 15th June, 2017. Information regarding this issue will be updated once the solution details are available. For updates refer to http://www.arachni-scanner.com/blog/tag/release/");

  script_xref(name: "URL" , value: "http://seclists.org/fulldisclosure/2017/May/5");
  script_tag(name:"solution_type", value:"NoneAvailable");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("Web application abuses");

  script_dependencies("gb_arachni_detect.nasl");
  script_mandatory_keys("arachni/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!Port = get_app_port(cpe: CPE)) exit(0);


if(!Ver = get_app_version(cpe: CPE, port: Port))  exit(0);

if(!Webui = get_kb_item("arachni/webui")) exit(0);

if(version_is_equal(version: Ver, test_version: "1.5") && version_is_equal(version: Webui, test_version: "0.5.11"))

{
  report =  report_fixed_ver(installed_version: Ver, fixed_version: "None Available");
  security_message(data: report, port: Port);
  exit(0);
}

exit (99);
