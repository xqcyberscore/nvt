###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_logitech_media_server_dom_xss_vuln.nasl 8368 2018-01-11 07:59:53Z asteins $
#
# Logitech Media Server DOM Based XSS Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.811878");
  script_version("$Revision: 8368 $");
  script_cve_id("CVE-2017-15687");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-01-11 08:59:53 +0100 (Thu, 11 Jan 2018) $");
  script_tag(name:"creation_date", value:"2017-10-24 18:15:51 +0530 (Tue, 24 Oct 2017)");
  script_name("Logitech Media Server DOM Based XSS Vulnerability");

  script_tag(name:"summary", value:"This host is running Logitech Media Server
  and is prone to a dom based cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient
  validation of user supplied input via url.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  users to execute arbitrary script code in the browser of an unsuspecting user 
  in the context of the affected site. This may allow the attacker to steal 
  cookie-based authentication credentials and launch other attacks.

  Impact Level: Application");

  script_tag(name:"affected", value:"Logitech Media Server versions 7.7.3,
  7.7.5, 7.9.1, 7.7.2, 7.7.1, 7.7.6 and 7.9.0");

  script_tag(name:"solution", value:"No solution or patch is available as of
  11th January, 2018. Information regarding this issue will be updated once 
  solution details are available. For updates refer to https://www.logitech.com.");


  script_tag(name:"solution_type", value:"NoneAvailable");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name : "URL" , value : "https://fireshellsecurity.team/assets/pdf/DOM-Based-Cross-Site-Scripting-_XSS_-Logitech-Media-Server.pdf");
  script_xref(name : "URL" , value : "https://www.exploit-db.com/exploits/43024");
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

if(!logVer = get_app_version(cpe:CPE, port:logPort)){
  exit(0);
}

foreach affected_version (make_list("7.7.3", "7.7.5", "7.9.1", "7.7.2", "7.7.1", "7.7.6", "7.9.0"))
{
  if(affected_version == logVer)
  {
    report = report_fixed_ver(installed_version:logVer, fixed_version:"NoneAvailable");
    security_message(data:report, port:logPort);
    exit(0);
  }
}
exit(0);
