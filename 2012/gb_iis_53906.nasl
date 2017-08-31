###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_iis_53906.nasl 6720 2017-07-13 14:25:27Z cfischer $
#
# Microsoft IIS Authentication Bypass and Source Code Disclosure Vulnerabilities
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

CPE = "cpe:/a:microsoft:iis";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103507");
 script_bugtraq_id(53906);
 script_version ("$Revision: 6720 $");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("Microsoft IIS Authentication Bypass and Source Code Disclosure Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/53906");
 script_xref(name : "URL" , value : "http://www.microsoft.com/windowsserver2003/iis/default.mspx");

 script_tag(name:"last_modification", value:"$Date: 2017-07-13 16:25:27 +0200 (Thu, 13 Jul 2017) $");
 script_tag(name:"creation_date", value:"2012-07-03 10:23:40 +0200 (Tue, 03 Jul 2012)");
 script_category(ACT_ATTACK);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("secpod_ms_iis_detect.nasl","webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("IIS/installed");

 script_tag(name : "summary" , value : "Microsoft IIS is prone to an authentication-bypass vulnerability and a
 source-code disclosure vulnerability because it fails to properly sanitize user-supplied input.");
 script_tag(name : "insight" , value : "An attacker can exploit these vulnerabilities to gain unauthorized
 access to password-protected resources and view the source code of files in the context of the server
 process; this may aid in further attacks.");
 script_tag(name : "affected" , value : "Microsoft IIS 6.0 and 7.5 are vulnerable; other versions may also
 be affected.");

 script_tag(name:"qod_type", value:"remote_vul");
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))exit(0);

auth_req = get_kb_list("www/" + port + "/content/auth_required");
if(!auth_req) exit(0);

protected = make_list(auth_req);

files = make_list("/index.php","/admin.php","/login.php","/default.asp","/login.asp");

asp_ia = ":$i30:$INDEX_ALLOCATION";
php_ia = "::$INDEX_ALLOCATION";

x = 0;

foreach p (protected) {

  x++;

  if(ereg(pattern:"/$", string:p)) {

     p = ereg_replace(string:p, pattern:"/$", replace:"");

     foreach file (files) {

       if(".asp" >< file) {
         ia = asp_ia;
       } else {
         ia = php_ia;
       } 

       url = p + file; 

       buf = http_get_cache(item:url, port:port);

       if(buf !~ "HTTP/1.. 401")continue;

       url =  p + ia + file;

       req = http_get(item:url, port:port);
       buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

       if(buf =~ "HTTP/1.. 200") {
         security_message(port:port);
         exit(0);
       }  
    }  
  }  

  if(x > 5) {
    exit(0);
  }  

}  

exit(99);
