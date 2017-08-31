###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_liveupdate_administrator_mult_vuln.nasl 6663 2017-07-11 09:58:05Z teissa $
#
# Symantec LiveUpdate Administrator Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804359";
CPE = "cpe:/a:symantec:liveupdate_administrator";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6663 $");
  script_cve_id("CVE-2014-1644", "CVE-2014-1645");
  script_bugtraq_id(66399, 66400);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-11 11:58:05 +0200 (Tue, 11 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-04-03 15:36:12 +0530 (Thu, 03 Apr 2014)");
  script_name("Symantec LiveUpdate Administrator Multiple Vulnerabilities");

  tag_summary =
"The host is installed with Symantec LiveUpdate Administrator and is prone to
multiple vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Multiple flaws are due to,
- Improper restrictions on access to the 'lua/forcepasswd.do' script.
- Improper sanitization of input passed to 'lua/forcepasswd.do' and
'loginforgotpwd' scripts.";

  tag_impact =
"Successful exploitation will allow remote attackers to bypass certain security
restrictions and inject or manipulate SQL queries in the back-end database,
allowing for the manipulation or disclosure of arbitrary data.

Impact Level: Application";

  tag_affected =
"Symantec LiveUpdate Administrator before version 2.x before 2.3.2.110";

  tag_solution =
"Upgrade to Symantec LiveUpdate Administrator version 2.3.2.110 or later,
For updates refer to http://www.symantec.com";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/57659");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1029972");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/125925");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2014-03/0172.html");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_symantec_liveupdate_administrator_detect.nasl");
  script_mandatory_keys("Symantec/LUA/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
url = "";
sndReq = "";
rcvRes = "";
luaVer = "";
luaPort = "";

## Get Port
if(!luaPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Check port state
if(!get_port_state(luaPort)){
  exit(0);
}

## Get the version
if(!luaVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:luaPort)){
  exit(0);
}

if(version_in_range(version:luaVer, test_version:"2.0", test_version2:"2.3.2.109"))
{
  security_message(port:luaPort);
  exit(0);
}
