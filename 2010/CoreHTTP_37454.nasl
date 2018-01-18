###############################################################################
# OpenVAS Vulnerability Test
# $Id: CoreHTTP_37454.nasl 8438 2018-01-16 17:38:23Z teissa $
#
# CoreHTTP CGI Support Remote Command Execution Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "CoreHTTP is prone to a remote command-execution vulnerability because
the software fails to adequately sanitize user-supplied input.

Successful attacks can compromise the affected software and possibly
the computer.

CoreHTTP 0.5.3.1 is vulnerable; other versions may also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100418");
 script_version("$Revision: 8438 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-01-04 18:09:12 +0100 (Mon, 04 Jan 2010)");
 script_bugtraq_id(37454);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("CoreHTTP CGI Support Remote Command Execution Vulnerability");


 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("corehttp/banner");
 script_require_ports("Services/www", 5555);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37454");
 script_xref(name : "URL" , value : "http://corehttp.sourceforge.net/");
 script_xref(name : "URL" , value : "http://aconole.brad-x.com/advisories/corehttp.txt");
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:5555);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);

if(egrep(pattern:"Server: corehttp", string:banner)) {
  version = eregmatch(pattern: "Server: corehttp-([0-9.]+)", string: banner);
  if(!isnull(version[1])) {
    if(version_is_equal(version: version[1], test_version: "0.5.3.1")) {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(0);
