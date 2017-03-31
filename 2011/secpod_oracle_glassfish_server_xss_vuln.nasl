###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_oracle_glassfish_server_xss_vuln.nasl 5351 2017-02-20 08:03:12Z mwiegand $
#
# Oracle GlassFish Server Cross-Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.
  Impact Level: Application";
tag_affected = "Oracle GlassFish Server version 2.1.1";
tag_insight = "The flaw is due to error in the handling of log viewer, which fails
  to securely output encode logged values. An unauthenticated attacker can
  trigger the application to log a malicious string by entering the values
  into the username field.";
tag_solution = "Apply the security updates.
  http://www.oracle.com/technetwork/topics/security/whatsnew/index.html";
tag_summary = "The host is running GlassFish Server and is prone to cross-site
  scripting vulnerability.";

if(description)
{
  script_id(902456);
  script_version("$Revision: 5351 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 09:03:12 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)");
  script_cve_id("CVE-2011-2260");
  script_bugtraq_id(48797);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("Oracle GlassFish Server Cross-Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17551/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/518923");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103167/SOS-11-009.txt");

  script_tag(name:"qod_type", value:"remote_banner");
  script_summary("Check for the version of Oracle GlassFish Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web Servers");
  script_dependencies("GlassFish_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");
include("version_func.inc");

## Check for the default port
if(!port = get_http_port(default:8080)){
  port = 8080;
}

## Check port status
if(!get_port_state(port)){
  exit(0);
}

## Get the version form KB
vers = get_kb_item(string("www/", port, "/GlassFish"));
if(!isnull(vers))
{
  if(version_is_equal(version: vers, test_version:"2.1.1"))
  {
    security_message(port:port);
    exit(0);
  }
}
