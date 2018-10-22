##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cubecart_mult_xss_n_sql_inj_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# CubeCart Multiple Cross-Site Scripting and SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802199");
  script_version("$Revision: 11997 $");
  script_cve_id("CVE-2010-4903");
  script_bugtraq_id(43114);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-04 11:10:29 +0200 (Fri, 04 Nov 2011)");
  script_name("CubeCart Multiple Cross-Site Scripting and SQL Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/41352");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/513572/100/0/threaded");
  script_xref(name:"URL", value:"http://www.acunetix.com/blog/web-security-zone/articles/sql-injection-xss-cubecart-4-3-3/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site and
  manipulate SQL queries by injecting arbitrary SQL code.");
  script_tag(name:"affected", value:"CubeCart version 4.3.3");
  script_tag(name:"insight", value:"The flaws are due to

  - Input passed to the 'amount', 'cartId', 'email', 'transId', and
    'transStatus' parameters in 'modules/gateway/WorldPay/return.php' is not
    properly sanitised before being returned to the user.

  - Input passed via the 'searchStr' parameter to index.php
    (when '_a' is set to 'viewCat') is not properly sanitised before being used
    in a SQL query.");
  script_tag(name:"solution", value:"Upgrade to CubeCart version 4.4.2 or later");
  script_tag(name:"summary", value:"This host is running CubeCart and is prone to SQL injection and
  multiple cross-site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.cubecart.com/tour");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/cart", "/store", "/shop", "/cubecart", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  req = http_get(item: string(dir, "/admin.php?_g=login&goto=%2Fcubecart%2F" +
                        "admin.php"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  if("<title>CubeCart" >< res)
  {
    url = string(dir, "/index.php?searchStr='&_a=viewCat&Submit=Go");

    if(http_vuln_check(port:port, url:url, pattern:"You have an error " +
              "in your SQL syntax;", extra_check:"> SELECT id FROM cube_" +
              "CubeCart_search WHERE searchstr="))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);