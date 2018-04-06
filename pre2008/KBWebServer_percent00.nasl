# OpenVAS Vulnerability Test
# $Id: KBWebServer_percent00.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: KF Web Server /%00 bug
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# starting from roxen_percent.nasl
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

tag_summary = "Requesting a URL with '/%00' appended to it
makes some versions of KF Web Server to dump the listing of the  
directory, thus showing potentially sensitive files.";

tag_solution = "upgrade to the latest version of KF Web Server";

# References:
# From:"Securiteinfo.com" <webmaster@securiteinfo.com>
# To:nobody@securiteinfo.com
# Date: Sun, 7 Jul 2002 21:42:47 +0200 
# Message-Id: <02070721424701.01082@scrap>
# Subject: [VulnWatch] KF Web Server version 1.0.2 shows file and directory content

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11166");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 name = "KF Web Server /%00 bug";
 
 script_name(name);
 

 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

buffer = http_get(item:"/%00", port:port);
data   = http_keepalive_send_recv(port:port, data:buffer);
if ( data == NULL ) exit(0);


if (egrep(string: data, pattern: ".*File Name.*Size.*Date.*Type.*"))
{
 security_message(port);
}
