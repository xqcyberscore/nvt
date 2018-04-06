###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_orion_npm_mult_xss_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# SolarWinds Orion NPM Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attacker to execute arbitrary
HTML and script code in a user's browser session in the context of a vulnerable
site. This may allow an attacker to steal cookie-based authentications and
launch further attacks.

Impact Level: Application";

tag_affected = "SolarWinds Orion Network Performance Monitor (NPM) 10.1.2 SP1";

tag_insight = "The flaws are due to an input validation error in
NetPerfMon/CustomChart.aspx and NetPerfMon/MapView.aspx pages when processing
the 'Title' parameter.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running SolarWinds Orion NPM and is prone to cross
site scripting vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801986");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-09-20 15:38:54 +0200 (Tue, 20 Sep 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("SolarWinds Orion NPM Multiple Cross Site Scripting Vulnerabilities");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2011/Sep/107");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/105020/orionsolarwinds-xss.txt");
  script_xref(name : "URL" , value : "http://www.derkeiler.com/Mailing-Lists/Full-Disclosure/2011-09/msg00144.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_orion_npm_detect.nasl");
  script_require_ports("Services/www", 8787);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

## Check for the default port
port = get_http_port(default:8787);
if(!get_port_state(port)){
  exit(0);
}

## Check for the asp support
if(!can_host_asp(port:port)){
  exit(0);
}

## Get the version from KB
vers = get_version_from_kb(port:port,app:"orion_npm");
if(vers)
{
  ver = ereg_replace(pattern:" ", replace:".", string:vers);

  ## Check vulnerable version
  if(version_is_equal(version: ver, test_version: "10.1.2.SP1")){
    security_message(port:port);
  }
}
