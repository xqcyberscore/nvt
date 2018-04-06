# OpenVAS Vulnerability Test
# $Id: webserver4d.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Webserver 4D Cleartext Passwords
#
# Authors:
# Jason Lidow <jason@brandx.net>
#
# Copyright:
# Copyright (C) 2002 Jason Lidow <jason@brandx.net>
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

tag_solution = "Contact http://www.mdg.com for an update.";

tag_summary = "The remote host is running Webserver 4D 3.6 or lower.
  
Version 3.6 of this service stores all usernames and passwords in cleartext. 
File: C:\Program Files\MDG\Web Server 4D 3.6.0\Ws4d.4DD

A local attacker may use this flaw to gain unauthorized privileges
on this host.";


# The vulnerability was originally discovered by ts@securityoffice.net 

if(description)
{
        script_oid("1.3.6.1.4.1.25623.1.0.11151");
        script_version("$Revision: 9348 $");
        script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
        script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
        script_bugtraq_id(5803);
	script_cve_id("CVE-2002-1521");
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
        script_name("Webserver 4D Cleartext Passwords");





        script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");


        script_copyright("This script is Copyright (C) 2002 Jason Lidow <jason@brandx.net>");
        script_family("Web Servers");
        script_dependencies("gb_get_http_banner.nasl", "httpver.nasl", "no404.nasl");
        script_mandatory_keys("Web_Server_4D/banner");
        script_require_ports("Services/www", 80);
        script_tag(name : "solution" , value : tag_solution);
        script_tag(name : "summary" , value : tag_summary);
        exit(0);
}


include("http_func.inc");
port = get_http_port(default:80);


banner = get_http_banner(port:port);


poprocks = egrep(pattern:"^Server.*", string: banner);
if(banner)
{
        if("Web_Server_4D" >< banner) 
	{
                yo = string("The following banner was received: ", poprocks, "\n\nVersion 3.6 and lower of Webserver 4D stores all usernames and passwords in cleartext.\n\nFile: C:\\Program Files\\MDG\\Web Server 4D 3.6.0\\Ws4d.4DD\n\nRisk Factor: Low\nSolution: Contact http://www.mdg.com for an update.");
                security_message(port:port, data:yo);
 	}
}
