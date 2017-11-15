###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_scrumworkpro_rce.nasl 7764 2017-11-15 06:26:49Z cfischer $
#
# ScrumWorks Pro Remote Code Execution Vulnerability
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

CPE = 'cpe:/a:collabnet:scrumworkspro';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107181");
  script_version("$Revision: 7764 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-15 07:26:49 +0100 (Wed, 15 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-09-25 13:57:36 +0200 (Mon, 25 Sep 2017)");

  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name(" ScrumWorks Pro Remote Code Execution Vulnerability");

  script_tag(name: "summary", value: "The host is installed with ScrumWorks Pro and is prone to Remote Code Execution Vulnerability.");

  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight", value: "ScrumWorks Pro is prone to remote code execution vulnerability due to unsafe deserialization of bytes on the server side which lead to java deserialization attack.");
  script_tag(name: "impact" , value: "Remote attacker is able to execute arbitrary code with the permissions of the ScrumWorks application server.");

  script_tag(name: "affected", value: "ScrumWorks Pro version 6.7.0");
  script_tag(name: "solution", value: "No solution or patch is available as of 15th November, 2017. Information regarding this issue will be updated once the solution details are available.");

  script_xref(name: "URL" , value: "https://blogs.securiteam.com/index.php/archives/3387");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("Web application abuses");

  script_dependencies("gb_scrumworkspro_detect.nasl");

  script_require_ports("Services/www", 8080);
  script_mandatory_keys("scrumworkspro/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");


if(!Port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!Ver = get_app_version(cpe:CPE, port: Port)){
  exit(0);
}

if(version_is_equal(version: Ver, test_version:"6.7.0"))
{
  report =  report_fixed_ver(installed_version:Ver, fixed_version:"Non Available");
  security_message(data:report);
  exit( 0 );
}

exit ( 99 );

