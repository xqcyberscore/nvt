###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vbulletin_search_mult_sql_inj_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# vBulletin Search UI Multiple SQL Injection Vulnerabilities
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

tag_impact = "Successful exploitation will allow attacker to cause SQL Injection attack
  and gain sensitive information.
  Impact Level: Application";
tag_affected = "Vbulletin versions 4.0.x through 4.1.3.";
tag_insight = "The flaw is caused by improper validation of user-supplied input via the
  'messagegroupid'  and 'categoryid' parameters in search.php, which allows
  attacker to manipulate SQL queries by injecting arbitrary SQL code.";
tag_solution = "Apply the patch from below link,
  https://www.vbulletin.com/forum/showthread.php/384249-vBulletin-4.X-Security-Patch";
tag_summary = "The host is running Vbulletin and is prone to multiple SQL
  injection vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902540");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)");
  script_bugtraq_id(48815);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("vBulletin Search UI Multiple SQL Injection Vulnerabilities");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/45290");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103198/vbulletinmgi-sql.txt");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103197/vbulletinsearchui-sql.txt");

  script_tag(name:"qod_type", value:"remote_active");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("vbulletin_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("vBulletin/installed");
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

port = get_http_port(default:80);

if(! dir = get_dir_from_kb(port:port, app:"vBulletin")){
  exit(0);
}

host = http_host_name( port:port );

## Construct attack request
attack = string("query=OpenVAS+SQL+Injection&titleonly=0&searchuser=&starter",
                "only=0&searchdate=0&beforeafter=after&sortby=dateline&order=",
                "descending&showposts=1&saveprefs=1&dosearch=Search+Now&s=&",
                "securitytoken=&searchfromtype=vBForum%3ASocialGroupMessage&",
                "do=process&contenttypeid=5&messagegroupid[0]='");

req = string("POST ", dir, "/search.php?search_type=1 HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", OPENVAS_HTTP_USER_AGENT, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(attack), "\r\n\r\n", attack);

## Try SQL injection Attack
res = http_keepalive_send_recv(port:port, data:req);

## Confirm exploit worked by checking the response
if('Database error' >< res && 'MySQL Error' >< res){
  security_message(port);
}
