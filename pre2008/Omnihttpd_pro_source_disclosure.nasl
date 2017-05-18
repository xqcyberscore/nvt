# OpenVAS Vulnerability Test
# $Id: Omnihttpd_pro_source_disclosure.nasl 6046 2017-04-28 09:02:54Z teissa $
# Description: OmniPro HTTPd 2.08 scripts source full disclosure
#
# Authors:
# Gregory Duchemin <plugin@intranode.com>
#
# Copyright:
# Copyright (C) 2001 INTRANODE
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

tag_solution = "The vendor is aware of the problem but so far, no
patch has been made available. Contact your web server vendor 
for a possible solution. Until a complete fix is available, you 
should remove all scripting files from non-executable directories.";

tag_summary = "OmniPro HTTPd 2.08 suffers from a security vulnerability that permits 
malicious users to get the full source code of scripting files.

By appending an ASCII/Unicode space char '%20' at the script suffix, 
the web server will no longer interpret it and rather send it back clearly 
as a simple document to the user in the same manner as it usually does to 
process HTML-like files.

The flaw does not work with files located in CGI directories (e.g cgibin, 
cgi-win)

Exploit: GET /test.php%20 HTTP/1.0

Vulnerable systems: up to release 2.08";

#### REGISTER SECTION ####

if(description)
{


script_id(10716);
script_version("$Revision: 6046 $");
script_cve_id("CVE-2001-0778");
script_tag(name:"last_modification", value:"$Date: 2017-04-28 11:02:54 +0200 (Fri, 28 Apr 2017) $");
script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
script_bugtraq_id(2788);
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
#Name used in the client window.

name = "OmniPro HTTPd 2.08 scripts source full disclosure";
script_name(name);


#Description appearing in the OpenVAS client window when clicking on the name.




#Summary appearing in the tooltips, only one line. 

summary="Check the presence of OmniPro HTTPd 2.08 scripts source disclosure.";

#Test among the firsts scripts, no risk to harm the remote host.

script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");



#CVE Index number

#script_cve_id("");



#Copyright stuff

script_copyright("Copyright (C) 2001 INTRANODE");

#Category in which attack must be stored.

family="Web application abuses";
script_family(family);


#Portscan the target and get back.

script_dependencies("gb_get_http_banner.nasl");
script_mandatory_keys("OmniHTTPd/banner");


#optimization, 
#Check the presence of at least one listening web server.

script_require_ports(80, "Services/www");
 
script_tag(name : "summary" , value : tag_summary);
script_tag(name : "solution" , value : tag_solution);
exit(0);
}


include("http_func.inc");


#### ATTACK CODE SECTION ####

#Mandatory

function check_header(probe, port)
{ 
soc = http_open_socket(port);
if(!soc) return(0); 

 request = http_get(item:probe, port:port); 
 send(socket:soc, data:request);
 response = http_recv(socket:soc);
 http_close_socket(soc); 

 regex_signature[0] = "^Server: OmniHTTPd.*$";

if (egrep(pattern:regex_signature[0], string:response)) return(1);
else return(0);

}



function check(poison, port)
{ 
soc = http_open_socket(port);
if(!soc) return(0); 

 request = http_get(item:poison, port:port); 
 send(socket:soc, data:request);
 response = http_recv(socket:soc);
 http_close_socket(soc); 

 regex_signature[2] = "<?"; 


# here, a php signature.

if (regex_signature[2] >< response) return(1);
else return(0);

}




#search web port in knowledge database
#default is port 80

port = get_http_port(default:80);


if(!get_port_state(port)) exit(0);

if ( ! get_port_state(port) ) exit(0);

banner = get_http_banner( port:port );
if("OmniHTTPd" >!< banner ) exit(0);

Egg = "%20 ";
signature = "test.php";

probe=string("/");
if (!check_header(probe:probe, port:port)) exit(0);


poison=string("/", signature, Egg);

if (check(poison:poison, port:port))
{
report="OmniPro HTTPd web server is online and contains a security 
vulnerability that allows anybody to see PHP, SSI and SHTML scripts sources.
OpenVAS was able to get a complete PHP source from your server.
OmniPro servers are vulnerable up to version 2.08, please check the official website 
for the lastest release/patch : http://www.omnicron.com
If no patches are made available, you should, at least, remove all your scripts 
from non executable directories.

Solution : none yet";
security_message(port:port, data:report);
}
else
{
report="
OmniPro HTTPd web server is online but OpenVAS could not detect its release number.
Because there is a serious security vulnerability permitting a full disclosure 
of PHP/SHTML/Perl scripts in 2.08 versions, we recommend you to quicly check the version you are
currently running and if vulnerable, to look at the official Omnicron website: http://www.omnicron.com ";
security_message(port:port, data:report);
}

