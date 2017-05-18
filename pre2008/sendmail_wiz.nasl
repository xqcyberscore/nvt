# OpenVAS Vulnerability Test
# $Id: sendmail_wiz.nasl 6056 2017-05-02 09:02:50Z teissa $
# Description: Sendmail WIZ
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2004 Michel Arboi
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

CPE = 'cpe:/a:sendmail:sendmail';

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.16024");
 script_version("$Revision: 6056 $");
 script_tag(name:"last_modification", value:"$Date: 2017-05-02 11:02:50 +0200 (Tue, 02 May 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2897);
 script_cve_id("CVE-1999-0145");
 script_xref(name:"OSVDB", value:"1877");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Sendmail WIZ");
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2004 Michel Arboi");
 script_family("SMTP problems");
 script_dependencies("gb_sendmail_detect.nasl");
 script_require_keys("SMTP/sendmail");
 script_require_ports("Services/smtp", 25, 465, 587);
 
 script_tag(name:"solution", value:"reconfigure it or upgrade your MTA.");
 script_tag(name:"summary", value:"Your MTA accepts the WIZ command. It must be a very old version
 of sendmail.");
 script_tag(name:"insight", value:"WIZ allows remote users to execute arbitrary commands as root
 without the need to log in.");

 script_tag(name:"solution_type", value:"VendorFix");
 script_tag(name:"qod_type", value:"remote_vul");

 exit(0);
}

#

include("smtp_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);

soc = open_sock_tcp(port);
if(! soc) exit(0);
b = smtp_recv_banner(socket:soc);
if ( ! b || "Sendmail" >!< b ) exit(0);
s = string("WIZ\r\n");
# We could also test the "KILL" function, which is related to WIZ if I
# understood correctly
send(socket:soc, data:s);
r = recv_line(socket:soc, length:1024);
if(ereg(string: r, pattern: "^2[0-9][0-9]")) {
    security_message(port:port);
    close(soc);
    exit(0);
}
close(soc);

exit(99);