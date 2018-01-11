###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_logitech_media_server_mult_stored_xss_vuln.nasl 8367 2018-01-11 07:32:43Z cfischer $
#
# Logitech Media Server Multiple Persistent XSS Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:logitech:media_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811895");
  script_version("$Revision: 8367 $");
  script_cve_id("CVE-2017-16568", "CVE-2017-16567");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-01-11 08:32:43 +0100 (Thu, 11 Jan 2018) $");
  script_tag(name:"creation_date", value:"2017-11-07 14:00:28 +0530 (Tue, 07 Nov 2017)");
  script_name("Logitech Media Server Multiple Persistent XSS Vulnerabilities");

  script_tag(name:"summary", value:"This host is running Logitech Media Server
  and is prone to multiple stored cross site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws exist due to an insufficient
  validation of user supplied input via new favorite field value in favorites 
  tab and new URL value in Radio URL tab.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  users to execute arbitrary script code in the browser of an unsuspecting user 
  in the context of the affected site. This may allow the attacker to steal 
  cookie-based authentication credentials and launch other attacks.

  Impact Level: Application");

  script_tag(name:"affected", value:"Logitech Media Server version 7.9.0");

  script_tag(name:"solution", value:"No solution or patch is available as of
  13th November, 2017. Information regarding this issue will be updated once 
  solution details are available. For updates refer to https://www.logitech.com.");


  script_tag(name:"solution_type", value:"NoneAvailable");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name : "URL" , value : "https://www.exploit-db.com/exploits/43123");
  script_xref(name : "URL" , value : "https://www.exploit-db.com/exploits/43122");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_logitech_media_server_detect.nasl");
  script_mandatory_keys("Logitech/Media/Server/Installed");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

logPort = "";
logVer = "";

if(!logPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:logPort, exit_no_version:TRUE)) exit(0);
logVer = infos['version'];
path = infos['location'];

if(logVer == "7.9.0")
{
  report = report_fixed_ver(installed_version:logVer, fixed_version:"NoneAvailable", install_path:path);
  security_message(data:report, port:logPort);
  exit(0);
}
exit(0);
