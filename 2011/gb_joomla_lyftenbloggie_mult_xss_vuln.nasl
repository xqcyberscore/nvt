##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_lyftenbloggie_mult_xss_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Joomla 'Lyftenbloggie' Component Cross-Site Scripting Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will let attackers to execute arbitrary
script code in the browser of an unsuspecting user in the context of the
affected site.

Impact Level: Application.";

tag_affected = "Joomla Lyftenbloggie component version 1.1.0";

tag_insight = "- Input passed via the 'tag' and 'category' parameters to
'index.php' (when 'option' is set to 'com_lyftenbloggie') is not properly
sanitised before being returned to the user.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Joomla and is prone to Multiple Cross Site
Scripting vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801741");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-02-15 08:14:35 +0100 (Tue, 15 Feb 2011)");
  script_cve_id("CVE-2010-4718");
  script_bugtraq_id(45468);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Joomla 'Lyftenbloggie' Component Cross-Site Scripting Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42677");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/96761/joomlalyftenbloggie-xss.txt");

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
include("version_func.inc");

joomlaPort = get_http_port(default:80);
if(!joomlaPort){
  exit(0);
}

if(!joomlaDir = get_dir_from_kb(port:joomlaPort, app:"joomla")){
  exit(0);
}

sndReq = http_get(item:string(joomlaDir, '/index.php?option=com_lyftenbloggie' +
               '&tag=<script>alert("OpenVAS-XSS-Testing")</script>'),port:joomlaPort);
rcvRes = http_send_recv(port:joomlaPort, data:sndReq);
if(rcvRes =~ "HTTP/1\.. 200" && '><script>alert("OpenVAS-XSS-Testing")</script><' >< rcvRes)
{
    security_message(joomlaPort);
    exit(0);
}
