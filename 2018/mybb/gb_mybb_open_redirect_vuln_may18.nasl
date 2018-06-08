###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mybb_open_redirect_vuln_may18.nasl 10145 2018-06-08 14:34:24Z asteins $
#
# MyBB Open Redirection Vulnerability-May18
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
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

CPE = "cpe:/a:mybb:mybb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813403");
  script_version("$Revision: 10145 $");
  script_cve_id("CVE-2018-10678");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-06-08 16:34:24 +0200 (Fri, 08 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-05-22 15:25:41 +0530 (Tue, 22 May 2018)");
  ## Affected only with with Microsoft Edge
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("MyBB Open Redirection Vulnerability-May18");

  script_tag(name: "summary" , value:"The host is installed with MyBB and is
  prone to open redirection vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists as application fails to
  properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct phishing attacks. Other attacks are also possible.

  Impact Level: Application");

  script_tag(name:"affected", value:"MyBB version 1.8.15");

  script_tag(name:"solution", value:"No known solution is available as of 28th May, 2018.
  Information regarding this issue will be updated once solution details are available.");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_xref(name : "URL" , value : "https://gist.github.com/MayurUdiniya/7aaa50b878d82b6aab6ed0b3e2b080bc");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_detect.nasl");
  script_mandatory_keys("MyBB/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE)){
  exit(0);
}

infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE );
version = infos['version'];
path = infos['location'];

if(version == "1.8.15")
{
  report = report_fixed_ver(installed_version:version, fixed_version:"NoneAvailable", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}
exit(0);
