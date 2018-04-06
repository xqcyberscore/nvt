# OpenVAS Vulnerability Test
# $Id: sscd_input.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: SunSolve CD CGI user input validation
#
# Authors:
# Michel Arboi <arboi@alussinan.org> 
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CAN
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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

tag_summary = "Sunsolve CD CGI scripts does not validate user input.
Crackers may use them to execute some commands on your system.

** Note: OpenVAS did not try to perform the attack.";

# References:
# Date:  Mon, 11 Mar 2002 12:46:06 +0700
# From: "Fyodor" <fyarochkin@trusecure.com>
# To: bugtraq@securityfocus.com
# Subject: SunSolve CD cgi scripts...
#
# Date: Sat, 16 Jun 2001 23:24:45 +0700
# From: Fyodor <fyodor@relaygroup.com>
# To: security-alert@sun.com
# Subject: SunSolve CD security problems..

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11066");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4269);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_cve_id("CVE-2002-0436");

 name = "SunSolve CD CGI user input validation";
 script_name(name);
 

 
 script_category(ACT_ATTACK);
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 8383);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:8383);

if (is_cgi_installed_ka(port: port, item:"/cd-cgi/sscd_suncourier.pl")) {
	security_message(port);
	exit(0);
}

if (is_cgi_installed_ka(port: port, item:"sscd_suncourier.pl")) {
	security_message(port);
	exit(0);
}
