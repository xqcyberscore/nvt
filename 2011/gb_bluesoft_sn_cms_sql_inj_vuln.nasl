##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bluesoft_sn_cms_sql_inj_vuln.nasl 7044 2017-09-01 11:50:59Z teissa $
#
# BlueSoft Social Networking CMS SQL Injection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.801957");
  script_version("$Revision: 7044 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-01 13:50:59 +0200 (Fri, 01 Sep 2017) $");
  script_tag(name:"creation_date", value:"2011-07-19 14:57:20 +0200 (Tue, 19 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("BlueSoft Social Networking CMS SQL Injection Vulnerability");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103119/socialnetworking-sql.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation will let attackers to manipulate SQL
  queries by injecting arbitrary SQL code.

  Impact Level: Application.");
  script_tag(name : "affected" , value : "BlueSoft Social Networking CMS.");
  script_tag(name : "insight" , value : "The flaw is due to input passed via the 'photo_id' parameter
  to 'user_profile.php', which is not properly sanitised before being used in a SQL query.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "This host is running BlueSoft Social Networking CMS and is prone
  to SQL injection vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/cms", "/cncms", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  ## Send and Receive the response
  rcvRes = http_get_cache(item: dir + "/index.php", port:port);

  ## Confirm the application
  if("Powered By" >< rcvRes && "The Social Networking CMS" >< rcvRes &&
     ">ShopBlueSoft.com<" >< rcvRes)
  {
    ## Construct the exploit request
    exploit = string(dir, "/user_profile.php?view=photo&photo_id='");
    sndReq = http_get(item: exploit, port:port);
    rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

    ## Check the source code of the function in response
    if("error in your SQL syntax;">< rcvRes)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);