# OpenVAS Vulnerability Test
# Description: JRun Sample Files
#
# Authors:
# H D Moore
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CVE
#
# Copyright:
# Copyright (C) 2001 Digital Defense Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10996");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1386);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2000-0539");
  script_name("JRun Sample Files");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 Digital Defense Inc.");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Sample files should never be left on production
  servers.  Remove the sample files and any other files that are not required.");

  script_tag(name:"summary", value:"This host is running the Allaire JRun web server
  and has sample files installed.");

  script_tag(name:"impact", value:"Several of the sample files that come with JRun contain serious
  security flaws. An attacker can use these scripts to relay web requests from this machine to
  another one or view sensitive configuration information.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

file[0] = "/cfanywhere/index.html";    res[0] = "CFML Sample";
file[1] = "/docs/servlets/index.html"; res[1] = "JRun Servlet Engine";
file[2] = "/jsp/index.html";           res[2] = "JRun Scripting Examples";
file[3] = "/webl/index.html";          res[3] = "What is WebL";

port = get_http_port(default:80);

for( i = 0; file[i]; i++) {

  url = file[i];
  pat = res[i];

  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(data:req, port:port);
  if(!res)
    continue;

  if(pat >< r) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);