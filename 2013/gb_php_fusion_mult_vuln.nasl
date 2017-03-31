###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_fusion_mult_vuln.nasl 3557 2016-06-20 08:07:14Z benallard $
#
# PHP-Fusion Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.803431");
  script_version("$Revision: 3557 $");
  script_cve_id("CVE-2013-1803", "CVE-2013-1804", "CVE-2013-1805", "CVE-2013-1806",
                "CVE-2013-1807", "CVE-2013-7375");
  script_bugtraq_id(58226, 58265, 58270);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-06-20 10:07:14 +0200 (Mon, 20 Jun 2016) $");
  script_tag(name:"creation_date", value:"2013-03-07 13:36:54 +0530 (Thu, 07 Mar 2013)");
  script_name("PHP-Fusion Multiple Vulnerabilities");

  script_tag(name : "summary" , value : "This host is installed with PHP-Fusion and is prone to multiple
  vulnerabilities.");
  script_tag(name : "vuldetect" , value : "Send a crafted data via HTTP GET request and check whether it is able
  execute sql query or not.");
  script_tag(name : "insight" , value : "Multiple Flaws exist in PHP-Fusion, For more details about the vulnerabilities
  refer the reference section.");
  script_tag(name : "impact" , value : "Successful exploitation will allow attackers to execute arbitrary web script
  or HTML in a user's browser session in the context of an affected site and
  manipulate SQL queries by injecting arbitrary SQL code or disclose or
  manipulation of arbitrary data.

  Impact Level: Application");
  script_tag(name : "affected" , value : "PHP-Fusion Version 7.02.05 and prior versions may also be affected");
  script_tag(name : "solution" , value : "Upgrade to PHP-Fusion Version 7.02.06 or later,
  For updates refer to http://www.php-fusion.co.uk/downloads.php");

  script_xref(name : "URL" , value : "http://secunia.com/52403");
  script_xref(name : "URL" , value : "http://secunia.com/52226");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Feb/149");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24562");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/120598/PHP-Fusion-7.02.05-XSS-LFI-SQL-Injection.html");
  script_summary("Check if PHP-Fusion is vulnerable to sql injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_dependencies("secpod_php_fusion_detect.nasl");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
http_port = "";
req = "";
res = "";
url = "";

## Get HTTP Port
http_port = get_http_port(default:80);

## Check Host Supports PHP
if(!can_host_php(port:http_port)){
  exit(0);
}

## Iterate over the possible directories
foreach dir (make_list_unique("/", "/php-fusion", "/phpfusion", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  ## Iterate over the  possible subdirectories
  foreach subdir (make_list("", "/files", "/php-files"))
  {
    ## Request for the news.php
    sndReq = http_get(item:string(dir + subdir, "/news.php"), port:http_port);
    rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

    ## confirm the PHP-Fusion installation
    if(egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes) &&
                     ("PHP-Fusion Powered" >< rcvRes))
    {
      ## Construct Attack Request
      url = dir + subdir + "/downloads.php?cat_id=1&orderby='SQL-Injection-Test";

      ## Try attack and check the response to confirm vulnerability
      if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
            pattern:"You have an error in your SQL syntax.*SQL-Injection-Test"))
      {
        security_message(port:http_port);
        exit(0);
      }
    }
  }
}

exit(99);