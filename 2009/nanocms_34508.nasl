###############################################################################
# OpenVAS Vulnerability Test
# $Id: nanocms_34508.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# NanoCMS '/data/pagesdata.txt' Password Hash Information Disclosure
# Vulnerability
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

tag_summary = "NanoCMS is prone to an information-disclosure vulnerability because
  it fails to validate access to sensitive files.

  An attacker can exploit this vulnerability to obtain sensitive
  information that may lead to further attacks.

  NanoCMS 0.4_final is vulnerable; other versions may also be
  affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100141");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-04-16 19:20:22 +0200 (Thu, 16 Apr 2009)");
 script_bugtraq_id(34508);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("NanoCMS '/data/pagesdata.txt' Password Hash Information Disclosure Vulnerability");


 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("nanocms_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34508");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!version = get_kb_item(string("www/", port, "/nanocms")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];
dir  = matches[2];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_equal(version: vers, test_version: "0.4")) {
    VULN = TRUE;
  }  

} else {  
# No version found, try to exploit.
  if(!isnull(dir)) {

       url = string(dir, "/data/pagesdata.txt"); 
       req = http_get(item:url, port:port);
       buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);  
       if( buf == NULL ) exit(0);

       if( buf == NULL )exit(0); 
       if(egrep(pattern:"password.*[a-f0-9]{32}", string: buf))
       {    
  	  VULN = TRUE;
       }
  }
}

if(VULN) {

  security_message(port:port);
  exit(0);

}  
exit(0);
