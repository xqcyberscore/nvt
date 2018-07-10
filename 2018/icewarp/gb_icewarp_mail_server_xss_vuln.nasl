##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_icewarp_mail_server_xss_vuln.nasl 10443 2018-07-06 12:04:26Z santu $
#
# IceWarp Mail Server Cross Site Scripting Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:icewarp:mail_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813464");
  script_version("$Revision: 10443 $");
  script_cve_id("CVE-2018-7475");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-07-06 14:04:26 +0200 (Fri, 06 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-04 15:17:55 +0530 (Wed, 04 Jul 2018)");
  script_name("IceWarp Mail Server Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is running IceWarp Mail Server
  and is prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight", value:"The flaw exists due to insufficient
  sanitization of input in 'webdav/ticket/' URI.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to inject and execute arbitrary web script or HTML.

  Impact Level: Application");

  script_tag(name: "affected" , value:"IceWarp Mail Server version 12.0.3");

  script_tag(name: "solution" , value:"No known solution is available as
  of 04th June, 2018. Information regarding this issue will be updated once
  solution details are available. For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name : "URL" , value : "https://dinhbaoluciusteam.wordpress.com/2018/06/21/cve-2018-7475");
  script_xref(name : "URL" , value : "https://www.icewarp.com/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_icewarp_web_detect.nasl");
  script_mandatory_keys("icewarp/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!appPort = get_app_port(cpe:CPE)){
  exit(0);
}

infos = get_app_version_and_location( cpe:CPE, port:appPort, exit_no_version:TRUE );
appVer = infos['version'];
appPath = infos['location'];

if(appVer == "12.0.3")
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:"None Available", install_path:appPath);
  security_message(port:appPort, data: report);
  exit(0);
}
exit(0);
