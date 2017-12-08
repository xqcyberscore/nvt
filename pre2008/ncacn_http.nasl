# OpenVAS Vulnerability Test
# $Id: ncacn_http.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Detect CIS ports
#
# Authors:
# Georges Dagousset <georges.dagousset@alert4web.com>
#
# Copyright:
# Copyright (C) 2001 Alert4Web.com
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

tag_summary = "This detects the CIS ports by connecting to the server and
processing the buffer received.

CIS (COM+ Internet Services) are RPC over HTTP tunneling
and requires IIS to operate.
CIS ports shouldn't be visible on internet but only behind a firewall.

If you do not use this service, then disable it as it may become
a security threat in the future, if a vulnerability is discovered.";

tag_solution = "Disable CIS with DCOMCNFG or protect CIS ports by a Firewall.
http://support.microsoft.com/support/kb/articles/Q282/2/61.ASP

For more information about CIS:
http://msdn.microsoft.com/library/en-us/dndcom/html/cis.asp";


if(description)
{
 script_id(10761);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 name = "Detect CIS ports";
 script_name(name);
 

 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2001 Alert4Web.com");
 family = "Service detection";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports("Services/ncacn_http");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/ncacn_http");
if (!port)exit(0);

key = string("ncacn_http/banner/", port);
banner = get_kb_item(key);
if(banner)
{
 data = string("There is a CIS (COM+ Internet Services) on this port\nServer banner :\n", banner);
 log_message(port:port, data:data);
}
