# OpenVAS Vulnerability Test
# $Id: foxweb_dll.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: foxweb CGI
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

tag_summary = "The foxweb.dll or foxweb.exe CGI is installed. 
 
Versions 2.5 and below of this CGI program have a security flaw 
that lets an attacker execute arbitrary code on the remote server.

** Since OpenVAS just verified the presence of the CGI but could
** not check the version number, this might be a false alarm.";

tag_solution = "remove it from /cgi-bin or upgrade it";

# References:
# Date:	 Fri, 05 Sep 2003 09:41:37 +0800
# From:	"pokleyzz" <pokleyzz@scan-associates.net>
# To:	bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: [SCAN Associates Sdn Bhd Security Advisory] Foxweb 2.5 bufferoverflow in CGI and ISAPI extension
#

if(description)
{
 script_id(11939);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(8547);
 script_cve_id("CVE-2010-1898");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 name = "foxweb CGI";
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

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

l = make_list("foxweb.dll", "foxweb.exe");
foreach cgi (l)
{
  res = is_cgi_installed_ka(item:cgi, port:port);
  if(res)
  {
    security_message(port);
    exit(0);	# As we might fork, we exit here
  }
}
