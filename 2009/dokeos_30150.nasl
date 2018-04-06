###############################################################################
# OpenVAS Vulnerability Test
# $Id: dokeos_30150.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Dokeos 'user_portal.php' Local File Include Vulnerability
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

tag_summary = "Dokeos is prone to a local file-include vulnerability because it
  fails to properly sanitize user-supplied input.

  An attacker can exploit this vulnerability to view local files or
  execute arbitrary local scripts on the vulnerable computer in the
  context of the webserver process.

  Please note that this issue affects only Dokeos running on Windows.

  Dokeos 1.8.5 is vulnerable; other versions may also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100155");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-04-23 21:21:19 +0200 (Thu, 23 Apr 2009)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2008-3363");
 script_bugtraq_id(30150);

 script_name("Dokeos 'user_portal.php' Local File Include Vulnerability");


 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("dokeos_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/30150");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!version = get_kb_item(string("www/", port, "/dokeos")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];
dir  = matches[2];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_equal(version: vers, test_version: "1.8.5")) {
    VULN = TRUE;
  }  

} else {  
# No version found, try to exploit.
  if(!isnull(dir)) {

       url = string(dir, "/user_portal.php?include=..\..\..\..\..\..\..\..\..\..\..\..\..\boot.ini%00.ht");
       req = http_get(item:url, port:port);
       buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
       if(buf == NULL )exit(0); 
       if(egrep(pattern:"\[boot loader\]", string: buf))
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
