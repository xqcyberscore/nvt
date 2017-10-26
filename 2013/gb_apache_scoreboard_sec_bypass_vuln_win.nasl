###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_scoreboard_sec_bypass_vuln_win.nasl 7548 2017-10-24 12:06:02Z cfischer $
#
# Apache HTTP Server Scoreboard Security Bypass Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "
  Impact Level: Application";

CPE = "cpe:/a:apache:http_server";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803744";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 7548 $");
  script_cve_id("CVE-2012-0031");
  script_bugtraq_id(51407);
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 14:06:02 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"creation_date", value:"2013-08-21 19:53:07 +0530 (Wed, 21 Aug 2013)");
  script_name("Apache HTTP Server Scoreboard Security Bypass Vulnerability (Windows)");

 tag_summary =
"The host is running Apache HTTP Server and is prone to security bypass
vulnerability.";

  tag_vuldetect =
"Get the installed version Apache HTTP Server with the help of detect NVT
and check it is vulnerable or not.";

  tag_insight =
"The flaw is due to an error in 'inscoreboard.c', certain type field within
a scoreboard shared memory segment leading to an invalid call to the free
function.";

  tag_impact =
"Successful exploitation will allow remote attacker to bypass certain security
restrictions. Other attacks are also possible.";

  tag_affected =
"Apache HTTP Server version before 2.2.22 on windows.";

  tag_solution =
"Upgrade to Apache HTTP Server 2.2.22 or later,
For updates refer to http://svn.apache.org";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://svn.apache.org/viewvc?view=revision&revision=1230065");
  script_xref(name : "URL" , value : "http://www.halfdog.net/Security/2011/ApacheScoreboardInvalidFreeOnShutdown");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_apache_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/installed","Host/runs_windows");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

# variable initialization
httpPort = 0;
httpVers = "";

# get the port
if(!httpPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)) exit(0);

# check the port state
if(!get_port_state(httpPort)) exit(0);

# get the version
if(!httpVers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:httpPort)) exit(0);

# check the version
if(httpVers && httpVers >!< "unknown" &&
   version_is_less(version:httpVers, test_version:"2.2.22"))
{
  security_message(port:httpPort);
  exit(0);
}
