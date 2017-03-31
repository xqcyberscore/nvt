###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symphony_cms_session_fixation_vuln.nasl 5212 2017-02-06 16:45:27Z teissa $
#
# Symphony CMS Session Fixation Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
CPE = "cpe:/a:symphony-cms:symphony_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807852");
  script_version("$Revision: 5212 $");
  script_cve_id("CVE-2016-4309");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-02-06 17:45:27 +0100 (Mon, 06 Feb 2017) $");
  script_tag(name:"creation_date", value:"2016-07-04 14:57:33 +0530 (Mon, 04 Jul 2016)");
  script_name("Symphony CMS Session Fixation Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Symphony CMS
  and is prone to session fixation vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to an error in
  application which does not use or call 'session_regenerate_id' function upon
  successful user authentication.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  attacker to preset any users PHPSESSID session identifier and access the
  affected application with the same level of access to that of the victim.

  Impact Level: Application");

  script_tag(name:"affected", value:"Symphony CMS version 2.6.7");

  script_tag(name:"solution", value:"No solution or patch is available as of 06th February, 2017. Information regarding this issue will be updated once
  solution details are available. For updates refer to
  http://www.getsymphony.com");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name : "URL" , value : "https://packetstormsecurity.com/files/137551");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_symphony_cms_detect.nasl");
  script_mandatory_keys("symphony/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
cmsPort = "";
cmsVer = "";

## get the port
if(!cmsPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get the version
if(!cmsVer = get_app_version(cpe:CPE, port:cmsPort)){
  exit(0);
}

## Check for vulnerable version
if(version_is_equal(version:cmsVer, test_version:"2.6.7"))
{
  report = report_fixed_ver(installed_version:cmsVer, fixed_version:"NoneAvailable");
  security_message(data:report, port:cmsPort);
  exit(0);
}
