###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpboard_mult_xss_vuln.nasl 5819 2017-03-31 10:57:23Z cfi $
#
# PHP Board Multiple XSS Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.805352");
  script_version("$Revision: 5819 $");
  script_cve_id("CVE-2015-2217");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-31 12:57:23 +0200 (Fri, 31 Mar 2017) $");
  script_tag(name:"creation_date", value:"2015-03-14 13:06:08 +0530 (Sat, 14 Mar 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("PHP Board Multiple XSS Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with PHP Board
  and is prone to multiple xss vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Flaws are due to the 'q' parameter in
  search.php script and 'avatar' parameter in profile.php script not validated
  before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in the context of an affected site.

  Impact Level: Application");

  script_tag(name:"affected", value:"PHP Board version 2.2.7.");

  script_tag(name: "solution" , value:"No Solution or patch is available as of
  13th March, 2015.Information regarding this issue will updated once the
  solution details are available.For updates refer to http://www.myupb.com");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/130684/Ultimate-PHP-Board-UPB-2.2.7-Cross-Site-Scripting.html");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

# Variable Initialization
http_port = "";
sndReq = "";
rcvRes = "";

http_port = get_http_port(default:80);

# Check Host Supports PHP
if(!can_host_php(port:http_port)){
  exit(0);
}

# Iterate over possible paths
foreach dir (make_list_unique("/", "/upb", "/chat/upb", cgi_dirs(port:http_port)))
{

  if( dir == "/" ) dir = "";
  url = dir + "/";
  rcvRes = http_get_cache(item:url, port:http_port);

  #Confirm Application
  if(rcvRes && rcvRes =~ "Powered by.*UPB")
  {
    #Construct Attack Request
    url1 = url + "search.php?q='><script>alert(document.cookie)</script>";

    # Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:http_port, url:url1, check_header:TRUE,
       pattern:"<script>alert\(document\.cookie\)</script>"))
     {
       report = report_vuln_url( port:http_port, url:url1 );
       security_message(port:http_port, data:report);
       exit(0);
     }
  }
}

exit(99);
