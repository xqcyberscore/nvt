###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_web_cookbook_mult_vuln.nasl 3561 2016-06-20 14:43:26Z benallard $
#
# Web Cookbook Multiple Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803437");
  script_version("$Revision: 3561 $");
  script_bugtraq_id(58441);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-06-20 16:43:26 +0200 (Mon, 20 Jun 2016) $");
  script_tag(name:"creation_date", value:"2013-03-14 13:10:16 +0530 (Thu, 14 Mar 2013)");
  script_name("Web Cookbook Multiple Vulnerabilities");

  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24742");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/120760/");
  script_xref(name : "URL" , value : "http://security-geeks.blogspot.in/2013/03/web-cookbook-sql-injection-xss.html");


  script_summary("Check if Web Cookbook is vulnerable to XSS vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation will allow attacker to execute arbitrary
  HTML or web script in a user's browser session in context of an affected site,
  compromise the application and inject or manipulate SQL queries in the
  back-end database,

  Impact Level: Application");
  script_tag(name : "affected" , value : "Web Cookbook versions 0.9.9 and prior");
  script_tag(name : "insight" , value : "Input passed via 'sstring', 'mode', 'title', 'prefix', 'postfix',
  'preparation', 'tipp', 'ingredient' parameters to searchrecipe.php,
  showtext.php, searchrecipe.php scripts is not properly sanitised before
  being returned to the user.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "This host is installed with Web Cookbook and is prone to
  multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port = "";
sndReq = "";
rcvRes = "";

## Get HTTP Port
port = get_http_port(default:80);

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over the possible directories
foreach dir (make_list_unique("/", "/cookbook", "/webcookbook", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  ## Request for the index.php
  sndReq = http_get(item:string(dir, "/index.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

  ## confirm the Application
  if(rcvRes && "/projects/webcookbook/" >< rcvRes)
  {
    ## Construct Attack Request
    url = dir + "/searchrecipe.php?mode=1&title=<script>alert('XSS-Test')</script>";

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, check_header:TRUE,
             pattern:"<script>alert\('XSS-Test'\)</script>"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);