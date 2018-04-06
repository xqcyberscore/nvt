# OpenVAS Vulnerability Test
# $Id: readdesigncheck.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: ReadDesign checker
#
# Authors:
# Hemil Shah
#
# Copyright:
# Copyright (C) 2000 - 2004 Net-Square Solutions Pvt Ltd.
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

tag_summary = "This plugin checks for ReadDesign vulns on the remote web server.

For more information, see:

https://www.appsecinc.com/Policy/PolicyCheck1520.html";

# Desc: This script will check for the ReadDesign vuln on names.nsf.

if(description)
{
	script_oid("1.3.6.1.4.1.25623.1.0.12249");
	script_version("$Revision: 9348 $");
	script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
	script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 	name = "ReadDesign checker";
 	script_name(name);
   script_tag(name:"cvss_base", value:"5.0");
   script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 	summary = "ReadDesign checker";
	script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
	script_copyright("This script is Copyright (C) 2004 Net-Square Solutions Pvt Ltd.");
	script_family("General");
	script_dependencies("find_service.nasl");
	script_require_ports("Services/www", 80);
 script_tag(name : "summary" , value : tag_summary);
	exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

exit(0); # broken

port = get_http_port(default:80);

if(! get_port_state(port))
    exit(0);

if ( get_kb_item("www/no404/" + port) ) exit(0);

dirs[0] = "/names.nsf";
dirs[1] = "/homepage.nsf";
dirs[2] = "/admin.nsf";
dirs[3] = "/admin4.nsf";
dirs[4] = "/smtp.nsf";
dirs[5] = "/reports.nsf";
dirs[6] = "/statmail.nsf";
dirs[7] = "/webadmin.nsf";

report = string("The ReadDesign vulnerability was found on the server.
Specifically, configuration information may be leaked which would aid
an attacker in future exploits\n");



for(i=0; dirs[i]; i++)
{   
	req = string(dirs[i], "/?ReadDesign");
	req = http_get(item:req, port:port);
	res = http_keepalive_send_recv(port:port, data:req);

	if ( res == NULL ) exit(0);

       
        if( ereg(pattern:"HTTP/1.[01] 200", string:res)  )
        {	
	    report = report + string("The following request triggered the vulnerability\n");
	    report = report + string(req, "\nRisk: Medium\n"); 
            report = report + string("See: https://www.appsecinc.com/Policy/PolicyCheck1520.html");
            security_message(port:port, data:report);            
            exit(0);
        }
}

