###############################################################################
# OpenVAS Vulnerability Test
# $Id: net2ftp_34440.nasl 9425 2018-04-10 12:38:38Z cfischer $
#
# net2ftp Multiple Cross-Site Scripting Vulnerabilities
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

tag_summary = "The net2ftp program is prone to multiple cross-site scripting
  vulnerabilities because it fails to properly sanitize user-supplied
  input.

  An attacker can exploit these issues to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the
  affected site. This may help the attacker steal cookie-based
  authentication credentials and launch other attacks.

  These issues affect net2ftp 0.98 and earlier.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100126");
 script_version("$Revision: 9425 $");
 script_bugtraq_id(34440);
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_tag(name:"last_modification", value:"$Date: 2018-04-10 14:38:38 +0200 (Tue, 10 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-04-12 20:09:50 +0200 (Sun, 12 Apr 2009)");
 script_name("net2ftp Multiple Cross-Site Scripting Vulnerabilities");


 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("net2ftp_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/49791");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34440");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!version = get_kb_item(string("www/", port, "/net2ftp")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];
dir  = matches[2];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less_equal(version: vers, test_version: "0.98")) {
    VULN = TRUE;
  }  

} else {  
# No version found, try to exploit.
  if(!isnull(dir)) {
     url = string(dir, '/index.php?state=login_small&errormessage=<script>alert(document.cookie)</script>');
     req = http_get(item:url, port:port);
     buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
     if( buf == NULL )continue;
     if(buf =~ "HTTP/1\.. 200" && egrep(pattern:"<script>alert\(document\.cookie\)</script>", string: buf))
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
