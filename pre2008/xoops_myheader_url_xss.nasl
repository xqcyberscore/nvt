# OpenVAS Vulnerability Test
# $Id: xoops_myheader_url_xss.nasl 3518 2016-06-14 13:05:54Z mime $
# Description: Xoops myheader.php URL Cross Site Scripting Vulnerability
#
# Authors:
# Noam Rathaus
# Updated: 05/07/2009 Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2003 Noam Rathaus
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

# From: Chintan Trivedi [chesschintan@hotmail.com]
# Subject: XSS vulnerability in XOOPS 2.0.5.1
# Date: Sunday 21/12/2003 16:45

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11962");
  script_version("$Revision: 3518 $");
  script_tag(name:"last_modification", value:"$Date: 2016-06-14 15:05:54 +0200 (Tue, 14 Jun 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9269);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Xoops myheader.php URL Cross Site Scripting Vulnerability");
  script_summary("Detect Xoops myheader.php URL XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "solution" , value : "Upgrade to the latest version of XOOPS.");
  script_tag(name : "summary" , value : "The weblinks module of XOOPS contains a file named 'myheader.php'
  in /modules/mylinks/ directory. The code of the module insufficently
  filters out user provided data. The URL parameter used by 'myheader.php'
  can be used to insert malicious HTML and/or JavaScript in to the web page.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

xoopsPort = get_http_port(default:80);

expRes = raw_string(0x22);

foreach path (make_list_unique("/", "/xoops/htdocs", "/xoops/htdocs/install", cgi_dirs(port:xoopsPort)))
{

  if(path == "/") path = "";

  rcvRes = http_get_cache(item: path + "/index.php", port:xoopsPort);

  if("XOOPS" >< rcvRes)
  {
    sndReq = http_get(item:string(path, "/modules/mylinks/myheader.php?url=" +
                                        "javascript:foo"), port:xoopsPort);
    rcvRes = http_keepalive_send_recv(port:xoopsPort, data:sndReq);
    if(rcvRes != NULL )
    {
      expRes = string("href=", expRes, "javascript:foo", expRes);
      if(rcvRes =~ "HTTP/1\.. 200" && expRes >< rcvRes )
      {
        security_message(port:xoopsPort);
        exit(0);
      }
    }
  }
}

exit(99);
