##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bluesoft_classifieds_script_sql_inj_vuln.nasl 7024 2017-08-30 11:51:43Z teissa $
#
# BlueSoft Classifieds Script SQL Injection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.801955");
  script_version("$Revision: 7024 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-30 13:51:43 +0200 (Wed, 30 Aug 2017) $");
  script_tag(name:"creation_date", value:"2011-07-19 14:57:20 +0200 (Tue, 19 Jul 2011)");
  script_bugtraq_id(48703);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("BlueSoft Classifieds Script SQL Injection Vulnerability");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103123/bluesoftclassifieds-sql.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation will let attackers to manipulate SQL
  queries by injecting arbitrary SQL code.

  Impact Level: Application.");
  script_tag(name : "affected" , value : "BlueSoft Classifieds script.");
  script_tag(name : "insight" , value : "The flaw is due to input passed via the 'c' parameter to
  'search.php',which is not properly sanitised before being used in a SQL query.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "This host is running BlueSoft Classifieds Script and is prone to
  SQL injection vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Get the port
port = get_http_port(default:80);

if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/script", "/demo", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  ## Construct the request
  rcvRes = http_get_cache(item: dir + "/index.php", port:port);

  ## Confirm the application
  if(">BlueSoft Classifieds Script</" >< rcvRes)
  {
    ## Construct the exploit request
    exploit = string(dir, "/search.php?c='");
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