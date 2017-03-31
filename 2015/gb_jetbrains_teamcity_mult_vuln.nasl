###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jetbrains_teamcity_mult_vuln.nasl 3497 2016-06-13 12:28:47Z benallard $
#
# Jetbrains Teamcity Multiple Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805444");
  script_version("$Revision: 3497 $");
  script_cve_id("CVE-2014-10036", "CVE-2014-10002");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-06-13 14:28:47 +0200 (Mon, 13 Jun 2016) $");
  script_tag(name:"creation_date", value:"2015-04-07 10:25:40 +0530 (Tue, 07 Apr 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Jetbrains Teamcity Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Jetbrains
  Teamcity and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is installed with vulnerable version or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:
  - The feed/generateFeedUrl.html script does not validate input to the
  'cameFromUrl' parameter before returning it to users.
  - An unspecified error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to create a specially crafted request that would execute arbitrary
  script code in a user's browser session and gain access to potentially
  sensitive information.

  Impact Level: Application");

  script_tag(name:"affected", value:"JetBrains TeamCity version before 8.1");

  script_tag(name: "solution" , value:"Upgrade to JetBrains TeamCity 8.1 or
  later. For updates refer to  http://www.jetbrains.com/teamcity/");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://www.netsparker.com/critical-xss-vulnerabilities-in-teamcity/");

  script_summary("Check for the vulnerable version of JetBrains TeamCity");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}



include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

# Variable Initialization
http_port = "";
tmcityVer = "";
version = "";
req = "";
buf = "";
url = "";

# Get HTTP Port
http_port = get_http_port(default:80);
if (!http_port) {
  http_port = 80;
}

# Check the port status
if(!get_port_state(http_port)){
  exit(0);
}

url = string("/login.html");
req = http_get(item:url, port:http_port);
buf = http_keepalive_send_recv(port:http_port, data:req, bodyonly:FALSE);

if(buf && 'content="TeamCity (Log in to TeamCity -- TeamCity)' >< buf ||
          '/<title/>Log in to TeamCity.*/</title/>' >< buf)
{
  ### try to get version
  version = eregmatch(string: buf, pattern: "Version</span> ([0-9.]+)",icase:TRUE);
  if (version[1]) {
      tmcityVer=chomp(version[1]);
  }

  ### checking for vulnerable version
  if(version_is_less(version:tmcityVer, test_version:"8.1"))
  {
    report = 'Installed version: ' + tmcityVer + '\n' +
             'Fixed version:     ' + "8.1" + '\n';
    security_message(data:report, port:http_port);
    exit(0);
  }
}
