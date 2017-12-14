# OpenVAS Vulnerability Test
# $Id: cross_site_scripting.nasl 8087 2017-12-12 13:12:04Z teissa $
# Description: Web Server Cross Site Scripting
#
# Authors:
# SecuriTeam (code was the "40x_cross_site.nasl")
# modified by CIRT.net (sq@cirt.net) (with help from SecuriTeam) to check
# for multiple cross site scripting vuls.
# Update by Felix Huber - huberfelix@webtopia.de - 14.11.2001
# Update by Chris Sullo - sq@cirt.net - 16.11.2001
# false positive fix by Andrew Hintz - http://guh.nu - 1.3.2002
# Update by rd: thanks to Andrew's remarks, HTTP headers are discared
# Update by Chris Sullo - sq@cirt.net - 06/27/2002 -- added .cfm test
#
# Copyright:
# Copyright (C) 2001 SecuriTeam, modified by Chris Sullo and Andrew Hintz
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "The remote web server seems to be vulnerable to a Cross Site Scripting
vulnerability (XSS). The vulnerability is caused by the result being
returned to the user when a non-existing file is requested (e.g. the
result contains script code provided in the request).

This vulnerability would allow an attacker to make the server present the
user with the attacker's JavaScript/HTML code.
Since the content is presented by the server, the user will give it the trust
level of the server (for example, the websites banks, shopping centers,
etc. would usually be trusted by a user).

Solutions:

. Allaire/Macromedia Jrun:
      - http://www.macromedia.com/software/jrun/download/update/ [^]
      - http://www.securiteam.com/windowsntfocus/Allaire_fixes_Cross-Site_Scripting_security_vulnerability.html [^]
. Microsoft IIS:
      - http://www.securiteam.com/windowsntfocus/IIS_Cross-Site_scripting_vulnerability__Patch_available_.html [^]
. Apache:
      - http://httpd.apache.org/info/css-security/ [^]
. Bluecoat CacheOS:
      - http://download.cacheflow.com/release/CA/4.1.00-docs/CACacheOS41fixes.htm [^]
. ColdFusion:
      - http://www.macromedia.com/v1/handlers/index.cfm?ID=23047 [^]
. General:
      - http://www.securiteam.com/exploits/Security_concerns_when_developing_a_dynamically_generated_web_site.html [^]
      - http://www.cert.org/advisories/CA-2000-02.html [^]";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10815");
 script_version("$Revision: 8087 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-12 14:12:04 +0100 (Tue, 12 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_name("Web Server Cross Site Scripting");

 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_analysis");
 script_family("Web Servers");
 script_copyright("Copyright (C) 2001 SecuriTeam, modified by Chris Sullo and Andrew Hintz");
 script_dependencies("find_service.nasl", "httpver.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

post[0] = ".jsp";
post[1] = ".shtml";
post[2] = ".thtml";
post[3] = ".cfm";
post[4] = ".php";
post[5] = "";
post[6] = "";
post[7] = "";
post[8] = "";
post[9] = "";
post[10] = "";



dir[0] = ".jsp";
dir[1] = ".shtml";
dir[2] = ".thtml";
dir[3] = ".cfm";
dir[4] = ".php";
dir[5] = "MAGIC";
dir[6] = ".jsp";
dir[7] = ".shtml";
dir[8] = ".thtml";
dir[9] = ".cfm";
dir[10] = ".php";

if(get_port_state(port))
{
 confirmtext = string("<SCRIPT>foo</SCRIPT>");
 for (i = 0; dir[i] ; i = i + 1)
 {
    if ( dir[i] == "MAGIC" )
	url = string("/", confirmtext);
    else
        url = string("/foo" , dir[i] , "?param=", confirmtext, post[i]);


    req = http_get(item:url, port:port);
    r   = http_keepalive_send_recv(port:port, data:req, bodyonly: TRUE);
    if(r =~ "HTTP/1\.. 200" && confirmtext >< r)
      {
       exploit_url = string("http://", get_host_name(), ":", port, url);
       report = "
 The remote web server seems to be vulnerable to the Cross Site Scripting vulnerability (XSS). The vulnerability is caused
by the result returned to the user when a non-existing file is requested (e.g. the result contains the JavaScript provided
in the request).
The vulnerability would allow an attacker to make the server present the user with the attacker's JavaScript/HTML code.
Since the content is presented by the server, the user will give it the trust
level of the server (for example, the trust level of banks, shopping centers, etc. would usually be high).

Sample url : " + exploit_url + "

Solutions:

. Allaire/Macromedia Jrun:
      - http://www.macromedia.com/software/jrun/download/update/
      - http://www.securiteam.com/windowsntfocus/Allaire_fixes_Cross-Site_Scripting_security_vulnerability.html
. Microsoft IIS:
      - http://www.securiteam.com/windowsntfocus/IIS_Cross-Site_scripting_vulnerability__Patch_available_.html
. Apache:
      - http://httpd.apache.org/info/css-security/
. ColdFusion:
      - http://www.macromedia.com/v1/handlers/index.cfm?ID=23047
. General:
      - http://www.securiteam.com/exploits/Security_concerns_when_developing_a_dynamically_generated_web_site.html
      - http://www.cert.org/advisories/CA-2000-02.html";
     
       security_message(port:port, data:report);
       set_kb_item(name:string("www/", port, "/generic_xss"), value:TRUE);
       exit(0);
      }
 }
}

