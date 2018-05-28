###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_media_manager_xss_vuln.nasl 9957 2018-05-25 09:29:47Z santu $
#
# Joomla! Core 'Media Manager' XSS Vulnerability (20180509)
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813406");
  script_version("$Revision: 9957 $");
  script_cve_id("CVE-2018-6378");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-05-25 11:29:47 +0200 (Fri, 25 May 2018) $");
  script_tag(name:"creation_date", value:"2018-05-23 11:12:14 +0530 (Wed, 23 May 2018)");
  script_name("Joomla! Core 'Media Manager' XSS Vulnerability (20180509)");

  script_tag(name:"summary", value:"This host is running Joomla and is prone
  to a cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to inadequate filtering
  of file and folder names in media manager.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct XSS attack.

  Impact Level: Application");

  script_tag(name:"affected", value:"Joomla core versions 1.5.0 through 3.8.7");

  script_tag(name:"solution", value:"Upgrade to Joomla version 3.8.8 or later.
  For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name : "URL" , value:"https://developer.joomla.org/security-centre/737-20180509-core-xss-vulnerability-in-the-media-manager.html");
  script_xref(name : "URL" , value:"https://www.joomla.org");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!jPort = get_app_port(cpe:CPE)){
  exit(0);
}

infos = get_app_version_and_location(cpe:CPE, port:jPort, exit_no_version:TRUE );
jVer = infos['version'];
path = infos['location'];

if(version_in_range(version:jVer, test_version:"1.5.0", test_version2:"3.8.7"))
{
  report = report_fixed_ver(installed_version:jVer, fixed_version:"3.8.8", install_path:path);
  security_message(port:jPort, data:report);
  exit(0);
}
exit(0);
