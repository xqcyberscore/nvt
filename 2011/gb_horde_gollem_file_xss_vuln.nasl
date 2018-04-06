###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_horde_gollem_file_xss_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Horde Gollem 'file' Cross-Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in context of an affected
  site.
  Impact Level: Application";
tag_affected = "Horde Gollem versions before 1.1.2";
tag_insight = "The flaw is caused by improper validation of user-supplied input via the
  'file' parameter to 'view.php', which allows attackers to execute arbitrary
  HTML and script code on the web server.";
tag_solution = "Upgrade to Horde Gollem version 1.1.2 or later,
  For updates refer to http://www.horde.org/download/app/?app=gollem";
tag_summary = "This host is running Horde Gollem and is prone to cross site
  scripting vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801870");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_cve_id("CVE-2010-3447");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Horde Gollem 'file' Cross-Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://bugs.horde.org/ticket/9191");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41624");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2523");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_horde_gollem_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!get_port_state(port)) {
  exit(0);
}

if(!can_host_php(port:port)){
  exit(0);
}

## Check for Horde Gollem versions prior to 1.1.2
if(vers = get_version_from_kb(port:port,app:"gollem"))
{
  if(version_is_less(version:vers, test_version:"1.1.2")){
    security_message(port:port);
  }
}
