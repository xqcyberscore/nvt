###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_myre_real_estate_sql_inj_vuln.nasl 7044 2017-09-01 11:50:59Z teissa $
#
# MYRE Real Estate Software URL SQL Injection Vulnerability
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902539");
  script_version("$Revision: 7044 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-01 13:50:59 +0200 (Fri, 01 Sep 2017) $");
  script_tag(name:"creation_date", value:"2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("MYRE Real Estate Software URL SQL Injection Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45255");
  script_xref(name : "URL" , value : "http://securityreason.com/wlb_show/WLB-2011070044");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103051/myrerealestate-sql.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation will allow attacker to cause SQL Injection
  attack and gain sensitive information.

  Impact Level: Application");
  script_tag(name : "affected" , value : "MYRE Real Estate Software.");
  script_tag(name : "insight" , value : "The flaw is caused by improper validation of user-supplied input
  via the URL to 'realestate/agent/' when viewing an agent, which allows attacker
  to manipulate SQL queries by injecting arbitrary SQL code.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "The host is running MYRE Real Estate Software and is prone to
  SQL injection vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);

## Check Host Supports PHP
if(!can_host_php(port:port)) {
  exit(0);
}

foreach dir(make_list_unique("/realestate", "/", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  ## Send and Receive the response
  res = http_get_cache(item: dir + "/index.php", port:port);

  ## Confirm the application
  if('MYRE Real Estate Software' >< res)
  {
    ## Try SQL injection and check the response to confirm vulnerability
    url = string(dir, "/agent/1'--abcd.html");

    if(http_vuln_check(port:port, url:url, check_header: TRUE,
                       pattern:'You have an error in your SQL syntax;'))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);