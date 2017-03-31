###############################################################################
# OpenVAS Vulnerability Test
# $Id: coppermine_34782.nasl 4574 2016-11-18 13:36:58Z teissa $
#
# Coppermine Photo Gallery 'css' Parameter Cross-Site Scripting
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

tag_summary = "Coppermine Photo Gallery is prone to a cross-site scripting
  vulnerability because the application fails to properly sanitize
  user-supplied input.

  An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the
  affected site. This may allow the attacker to steal cookie-based
  authentication credentials and to launch other attacks.

  Versions prior to Coppermine Photo Gallery 1.4.22 are vulnerable.";


if (description)
{
 script_id(100175);
 script_version("$Revision: 4574 $");
 script_tag(name:"last_modification", value:"$Date: 2016-11-18 14:36:58 +0100 (Fri, 18 Nov 2016) $");
 script_tag(name:"creation_date", value:"2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cve_id("CVE-2009-1616");
 script_bugtraq_id(34782);

 script_name("Coppermine Photo Gallery 'css' Parameter Cross-Site Scripting Vulnerability");


 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("coppermine_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34782");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!version = get_kb_item(string("www/", port, "/coppermine")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];
dir  = matches[2];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less(version: vers, test_version: "1.4.22")) {
    VULN = TRUE;
  }  

} else {  
# No version found, try to exploit.
  if(!isnull(dir)) {

       url = string(dir,'/docs/showdoc.php?css=1%3E%22%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E'); 
       req = http_get(item:url, port:port);
       buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

       if( buf == NULL )exit(0); 
       if(buf =~ "HTTP/1\.. 200" && egrep(pattern:"<script>alert(document\.cookie)</script>", string: buf))
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
