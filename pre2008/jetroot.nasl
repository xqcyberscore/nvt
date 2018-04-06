# OpenVAS Vulnerability Test
# $Id: jetroot.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: HP Jet Admin 6.5 or less Vulnerability
#
# Authors:
# Laurent FACQ (@u-bordeaux.fr)
#
# Copyright:
# Copyright (C) 2004 facq
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

tag_summary = "The remote HP Web Jetadmin is vulnerable to multiple exploits.  This includes,
but is not limited to, full remote administrative access.  An attacker
can execute code remotely with SYSTEM level (or root) privileges by invoking
the ExecuteFile function.  To further exacerbate this issue, there is working
exploit code for multiple vulnerabilities within this product.";

tag_solution = "The issues are resolved in HP Web Jetadmin version 7.5";

# Based on :  http://www.phenoelit.de/hp/JetRoot_pl.txt
#       " Phenoelit HP Web JetAdmin 6.5 remote\n".
#       " Linux root and Windows NT/2000 Administrator exploit\n".
#       " by FX of Phenoelit\n".
#       " Research done at BlackHat Singapore 2002\n\n";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.12227"); 
    script_version("$Revision: 9348 $");
    script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
    script_bugtraq_id(9973);
    script_tag(name:"cvss_base", value:"7.8"); 
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
    name = "HP Jet Admin 6.5 or less Vulnerability";
    script_name(name);


    summary = "HP JetAdmin 6.5 or less vulnerability";


    script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");

    script_copyright("Copyright (C) 2004 facq");

    family = "General";
    script_family(family);
    script_dependencies("find_service.nasl", "http_version.nasl");
    script_require_ports("Services/www", 8000);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_xref(name : "URL" , value : "http://www.phenoelit.de/stuff/HP_Web_Jetadmin_advisory.txt");
    script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/15989");
    exit(0);
}


include("http_func.inc");

# Check starts here

port = 8000;
if(!get_port_state(port))exit(0);

r = http_send_recv(port:port, data:string("GET /plugins/hpjwja/help/about.hts HTTP/1.0\r\n\r\n"));

if(r == NULL) { 
    #display ("\n\nexit null\n\n"); 
    exit(0); 
}

if((r =~ "HTTP/1.[01] 200") && ("Server: HP-Web-Server" >< r))
{
    r= ereg_replace(pattern:"<b>|</b>", string:r, replace: "<>");
    r= ereg_replace(pattern:"<[^>]+>", string:r, replace: "");
    r= ereg_replace(pattern:"[[:space:]]+", string:r, replace: " ");
    r= ereg_replace(pattern:" <>", string:r, replace: "<>");
    r= ereg_replace(pattern:"<> ", string:r, replace: "<>");

    #display(r); # debug
    #display("\n\n"); # debug

    if (
        (r =~ "<>HP Web JetAdmin Version<>6.5") # tested
        ||
        (r =~ "<>HP Web JetAdmin Version<>6.2") # not tested
        ||
        (r =~ "<>HP Web JetAdmin Version<>7.0") # not tested
        )

    {
        #display("\nhole \n"); # debug
        security_message(port);
    }
}

