##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opencart_sql_inj_vuln.nasl 5323 2017-02-17 08:49:23Z teissa $
#
# OpenCart SQL Injection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800734");
  script_version("$Revision: 5323 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-17 09:49:23 +0100 (Fri, 17 Feb 2017) $");
  script_tag(name:"creation_date", value:"2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_bugtraq_id(38605);
  script_cve_id("CVE-2010-0956");
  script_name("OpenCart SQL Injection Vulnerability");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1003-exploits/opencart-sql.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "insight" , value : "The flaw exists in 'index.php' as it fails to sanitize user
  supplied data before using it in an SQL query. Remote attackers could exploit
  this to execute arbitrary SQL commands via the page parameter.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "This host is running OpenCart and is prone to SQL Injection
  vulnerability.");
  script_tag(name : "impact" , value : "Successful exploitation will allow remote attackers to execute
  arbitrary SQL statements on the vulnerable system, which may leads to access
  or modify data, or exploit latent vulnerabilities in the underlying database.

  Impact Level: Application");
  script_tag(name : "affected" , value : "OpenCart version 1.3.2");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP port
openPort = get_http_port(default:80);

## Check Host Supports PHP
if(!can_host_php(port:openPort)){
  exit(0);
}

## Check for the exploit on OpenCart
foreach dir (make_list_unique("/opencart", "/" , cgi_dirs(port:openPort)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:openPort);

  if(rcvRes =~ "[Pp]owered [Bb]y [Oo]penCart")
  {
    ## Send an exploit and receive the response
    sndReq = http_get(item:string(dir, "/index.php?route=product/special&path" +
                                      "=20&page='"), port:openPort);
    rcvRes = http_keepalive_send_recv(port:openPort, data:sndReq);

    ## Check the response for SQL statements
    if(("SELECT *" >< rcvRes && "ORDER BY" >< rcvRes))
    {
      security_message(port:openPort);
      exit(0);
    }
  }
}

exit(99);