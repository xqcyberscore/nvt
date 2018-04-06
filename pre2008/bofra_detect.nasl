# OpenVAS Vulnerability Test
# $Id: bofra_detect.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Bofra Virus Detection
#
# Authors:
# Brian Smith-Sweeney (brian@smithsweeney.com)
# http://www.smithsweeney.com
#
# Copyright:
# Copyright (C) 2004 Brian Smith-Sweeney
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

tag_summary = "The remote host seems to have been infected with the Bofra virus or one of its 
variants, which infects machines via an Internet Explorer IFRAME exploit.  
It is very likely this system has been compromised.";

tag_solution = "Re-install the remote system.
";
# Created: 11/15/04
# Last Updated: 11/15/04

if(description)
{
        script_oid("1.3.6.1.4.1.25623.1.0.15746");
        script_version("$Revision: 9348 $");
        script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
        script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
        script_tag(name:"cvss_base", value:"10.0");
        script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
	script_cve_id("CVE-2004-1050");
	script_bugtraq_id(11515);
        name = "Bofra Virus Detection";

        summary = "Determines the presence of a Bofra virus infection resulting from an IFrame exploit";
        family = "Malware";
        script_name(name);
        script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
        script_copyright("This script is Copyright (C) 2004 Brian Smith-Sweeney");
        script_family(family);
	script_dependencies('http_version.nasl');
	script_require_ports(1639);
        script_tag(name : "solution" , value : tag_solution);
        script_tag(name : "summary" , value : tag_summary);
        script_xref(name : "URL" , value : "http://securityresponse.symantec.com/avcenter/venc/data/w32.bofra.c@mm.html");
        exit(0);
}
 
#
# User-defined variables
#
# This is where we saw Bofra; YMMV
port=1639;

#
# End user-defined variables; you should not have to touch anything below this
#

# Get the appropriate http functions
include("http_func.inc");
include("http_keepalive.inc");


if ( ! get_port_state ( port ) ) exit(0);

# Prep & send the http get request, quit if you get no answer
req = http_get(item:"/reactor",port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(0);
hex_res=hexstr(res);
if ("3c0049004600520041004d00450020005300520043003d00660069006c0065003a002f002f00" >< hex_res )
	security_message(port);
else {
	if (egrep(pattern:"<IFRAME SRC=file://",string:res)){
		security_message(port);
	}
}
