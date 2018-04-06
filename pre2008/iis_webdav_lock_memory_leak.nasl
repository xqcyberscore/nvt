# OpenVAS Vulnerability Test
# $Id: iis_webdav_lock_memory_leak.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: IIS 5.0 WebDav Memory Leakage
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

tag_solution = "Download Service Pack 2/hotfixes from Microsoft web
at http://windowsupdate.microsoft.com";

tag_summary = "The WebDav extensions (httpext.dll) for Internet Information
Server 5.0 contains a flaw that may allow a malicious user to
consume all available memory on the target server by sending 
many requests using the LOCK method associated to a non 
existing filename.
 
This concern not only IIS but the entire system since the flaw can 
potentially exhausts all system memory available.

Vulnerable systems: IIS 5.0 ( httpext.dll versions prior to 0.9.3940.21 )

Immune systems: IIS 5 SP2( httpext.dll version 0.9.3940.21)";

# Title: WebDab Extensions Memory Leakage in IIS5/Win2K using LOCK Method.

#### REGISTER SECTION ####

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10732");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2736);
 script_cve_id("CVE-2001-0337");

 script_name("IIS 5.0 WebDav Memory Leakage");

#Test it among the firsts scripts, no risk to harm the remote host.
script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");

script_copyright("Copyright (C) 2001 INTRANODE");

script_family("Denial of Service");


#Portscan the target/try SMB SP test  before executing this script.
script_dependencies("gb_get_http_banner.nasl");
script_mandatory_keys("IIS/banner");

#optimization, stop here if either no web service was found 
# by gb_get_http_banner.nasl plugin or no port 80 was open.

script_require_ports(80, "Services/www");

script_tag(name : "solution" , value : tag_solution);
script_tag(name : "summary" , value : tag_summary);
exit(0);
}



#### ATTACK CODE SECTION ####

include("http_func.inc");



function check(poison, port)
{ 
 soc = http_open_socket(port);
 if(!soc) exit(0); 

 send(socket:soc, data:poison);
 code = recv_line(socket:soc, length:1024);
 http_close_socket(soc); 

 signature = "HTTP/1.1 207";


 if((signature >< code)) 
	return(1);
    else 
	return(0);
}

port = get_http_port(default:80);


sig = get_http_banner(port:port);
if ( !egrep(pattern:"^Server:.*IIS", string:sig )) exit(0);

if(!get_port_state(port)) exit(0);



quote = raw_string(0x22);
poison = string("PROPFIND / HTTP/1.1\r\n",
    	     "Host: ", get_host_name(), "\r\n",
	     "Content-Type: text/xml\r\n",
	     "Content-Length: 110\r\n\r\n",
	     "<?xml version=", quote, "1.0", quote, "?>\r\n",
	     "<a:propfind xmlns:a=", quote, "DAV:", quote, ">\r\n",
	     " <a:prop>\r\n",
	     "  <a:displayname:/>\r\n",
	     " </a:prop>\r\n",
	     "</a:propfind>\r\n");


#Verify the presence of IIS 5.0, DAV module and a valid return server code.

if (!(check(poison:poison, port:port))) exit(0);

#Try to get a Service pack via the registry.
SP = get_kb_item("SMB/Win2K/ServicePack");

if (!SP)
{
report="IIS 5 is online but service Pack could not be determined.
Please check that SP2 is correctly installed to prevent the WebDav 
Memory Leakage DOS vulnerability.

Solution : SP2 and hotfix are available at 
http://www.microsoft.com/windows2000/downloads/servicepacks/sp2/default.asp.";

security_message(port:port, data:report);
}
else
{ 
if (("Service Pack 1" >< SP) || ("Beta2" >< SP) || ("Beta3" >< SP) || ("RC1" >< SP) || ("Build 2128" >< SP))
 {
report="
IIS 5 is online but the Service Pack 2 doesn't seem to be installed.
The WebDav Memory Leakage DOS vulnerability can potentially put the 
server to its knees.
Solution : SP2 and hotfix are available at 
http://www.microsoft.com/windows2000/downloads/servicepacks/sp2/default.asp.";
security_message(port:port, data:report);
 }
}

