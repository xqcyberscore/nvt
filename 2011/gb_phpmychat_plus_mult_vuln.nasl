###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmychat_plus_mult_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# phpMyChat Plus Multiple Vulnerabilities
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

tag_impact = "Successful exploitation will allow attacker to cause SQL Injection
attack, gain sensitive information about the database used by the web application
or can cause arbitrary code execution inside the context of the web application.

Impact Level: Application";

tag_affected = "phpMyChat Plus version 1.93";

tag_insight = "The flaws are due to:
- Improper sanitization of user supplied input through the 'CookieUsername'
  and 'CookieStatus' parameter in Cookie.
- Improper sanitization of user supplied input through the 'pmc_password'
  parameter in a printable action to avatar.php.";

tag_solution = "Upgrade to version 1.94 or later,
For updates refer to http://sourceforge.net/projects/phpmychat";

tag_summary = "This host is running MyChat Plus and is prone to multiple
vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801936");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-05-16 15:25:30 +0200 (Mon, 16 May 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("MyChat Plus Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17213/");
  script_xref(name : "URL" , value : "http://www.rxtx.nl/webapps-phpmychat-plus-1-93-multiple-vulnerabilities/");
  script_xref(name : "URL" , value : "http://www.l33thackers.com/Thread-webapps-phpMyChat-Plus-1-93-Multiple-Vulnerabilities");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)){
  exit(0);
}

foreach dir( make_list_unique( "/plus", "/phpMyChat", "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  res = http_get_cache(item:string(dir,"/index.php"), port:port);

  ## Confirm the application
  if("<TITLE>My WonderfulWideWeb Chat - phpMyChat-Plus</TITLE>" >< res)
  {
    req = http_get(item:string(dir, '/avatar.php?pmc_password="' +
                   '><script>alert("XSS-TEST")</script>'), port:port);

    res = http_keepalive_send_recv(port:port, data:req);

    ## Confirm exploit worked by checking the response
    if(res =~ "HTTP/1\.. 200" && '<script>alert("XSS-TEST")</script>' >< res)
    {
      security_message(port);
      exit(0);
    }
  }
}
