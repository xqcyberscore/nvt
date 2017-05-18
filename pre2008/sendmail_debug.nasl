# OpenVAS Vulnerability Test
# $Id: sendmail_debug.nasl 6063 2017-05-03 09:03:05Z teissa $
# Description: Sendmail DEBUG
#
# Authors:
# Renaud Deraison <deraison@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 1999 Renaud Deraison
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
 script_oid("1.3.6.1.4.1.25623.1.0.10247");
 script_version("$Revision: 6063 $");
 script_tag(name:"last_modification", value:"$Date: 2017-05-03 11:03:05 +0200 (Wed, 03 May 2017) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_bugtraq_id(1);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-1999-0095");
 script_name("Sendmail DEBUG");
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 1999 Renaud Deraison");
 script_family("SMTP problems");
 script_dependencies("gb_sendmail_detect.nasl");
 script_require_keys("SMTP/sendmail");
 script_require_ports("Services/smtp", 25, 465, 587);
 
 script_tag(name:"summary", value:"Your MTA accepts the DEBUG mode.

 This mode is dangerous as it allows remote users to execute arbitrary
 commands as root without the need to log in.");
 script_tag(name:"solution", value:"Upgrade your MTA.");

 script_tag(name:"solution_type", value:"VendorFix");
 script_tag(name:"qod_type", value:"remote_vul");

 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);

soc = open_sock_tcp(port);
if(soc)
{
  b = smtp_recv_banner(socket:soc);

  s = string("debug\r\n");
  send(socket:soc, data:s);
  r = recv_line(socket:soc, length:1024);
  r = tolower(r);

  
  if(("200 debug set" >< r)) {
    security_message(port:port);
    close(soc);
    exit(0);
  }
  close(soc);
}

exit(99);