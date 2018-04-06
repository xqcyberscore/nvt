# OpenVAS Vulnerability Test
# $Id: carello.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Carello detection
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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

tag_summary = "Carello.dll was found on your web server. 
Versions up to 1.3 of this web shopping cart allowed anybody
to run arbitrary commands on your server.

*** Note that no attack was performed, and the version number was
*** not checked, so this might be a false alert";

tag_solution = "Upgrade to the latest version if necessary";

# References:
#
# Date: Wed, 02 Oct 2002 17:10:21 +0100
# From: "Matt Moore" <matt@westpoint.ltd.uk>
# To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: wp-02-0012: Carello 1.3 Remote File Execution (Updated 1/10/2002)
#
# http://www.westpoint.ltd.uk/advisories/wp-02-0012.txt

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11776");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2729);
 script_cve_id("CVE-2001-0614");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");

 name = "Carello detection";

 script_name(name);
 

 
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003 Michel Arboi");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# Please note that it is possible to test this vulnerability, but
# I suspect that Carello is not widely used, and I am lazy :-)
# 
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);

res = is_cgi_installed_ka(item:"Carello.dll", port:port);
if (res) security_message(port);
