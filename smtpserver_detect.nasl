###############################################################################
# OpenVAS Vulnerability Test
# $Id: smtpserver_detect.nasl 11039 2018-08-17 12:26:47Z cfischer $
#
# SMTP Server type and version
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10263");
  script_version("$Revision: 11039 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 14:26:47 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SMTP Server type and version");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 1999 SecuriTeam");
  script_family("Service detection");
  script_dependencies("find_service_3digits.nasl");
  script_require_ports("Services/smtp", 25, 465, 587);

  script_tag(name:"summary", value:"This detects the SMTP Server's type and version by connecting to
  the server and processing the buffer received.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("smtp_func.inc");
include("host_details.inc");

port = get_kb_item( "Services/smtp" );
if( ! port ) port = 25;
if( ! get_port_state( port ) ) port = 465;
if( ! get_port_state( port ) ) port = 587;

if( get_port_state( port ) ) {

  soc = open_sock_tcp( port );

  if( soc ) {

    banner = smtp_recv_banner( socket:soc );

    if( ! banner ) {
      set_kb_item( name:"SMTP/wrapped", value:TRUE );
      close( soc );
      exit( 0 );
    }

    if( "220" >!< banner ) {
      # Doesn't look like SMTP...
      close( soc );
      exit( 0 );
    }

    send( socket:soc, data:'EHLO ' + this_host() + '\r\n' );
    ehlo = smtp_recv_line( socket:soc );
    if( ehlo ) set_kb_item( name:"smtp/" + port + "/ehlo", value: ehlo );

    send( socket:soc, data:'HELP\r\n' );
    help = smtp_recv_line( socket:soc );
    if( help ) set_kb_item( name:"smtp/" + port + "/help", value: help );

    send( socket:soc, data:'NOOP\r\n' );
    noop = smtp_recv_line( socket:soc );
    if( noop ) set_kb_item( name:"smtp/" + port + "/noop", value: noop );

    send( socket:soc, data:'RSET\r\n' );
    rset = smtp_recv_line( socket:soc );
    if( rset ) set_kb_item( name:"smtp/" + port + "/rset", value: rset );

    send( socket:soc, data:'QUIT\r\n' );
    quit = smtp_recv_line( socket:soc );
    if( quit ) set_kb_item( name:"smtp/" + port + "/quit", value: quit );

  if (("qmail" >< banner) || ("qmail" >< help))
  {
   set_kb_item(name:"SMTP/qmail", value:TRUE);
   guess = "Qmail";
  }

  if("XMail " >< banner)
  {
   set_kb_item(name:"SMTP/xmail", value:TRUE);
   guess = "XMail";
  }

  if(egrep(pattern:".*nbx.*Service ready.*", string:banner))
  {
   set_kb_item(name:"SMTP/3comnbx", value: TRUE);
  }

  if(("ZMailer Server" >< banner) ||
    (("This mail-server is at Yoyodyne Propulsion Inc." >< help) && # Default help text.
     ("Out" >< quit) && ("zmhacks@nic.funet.fi" >< help))) {
   set_kb_item(name:"SMTP/zmailer", value:TRUE);
   guess = "ZMailer";
   str = egrep(pattern:" ZMailer ", string:banner);
   if(str) {
     str=ereg_replace(pattern:"^.*ZMailer Server ([0-9a-z\.\-]+) .*$", string:str, replace:"\1");
     guess=string("ZMailer version ",str);
   }
  }

  if("CheckPoint FireWall-1" >< banner)
  {
   set_kb_item(name:"SMTP/firewall-1", value: TRUE);
   guess="CheckPoint FireWall-1";
  }

  if(("InterMail" >< banner) ||
    (("This SMTP server is a part of the InterMail E-mail system" >< help) &&
    ("Ok resetting state." >< rset) && ("ESMTP server closing connection." >< quit))) {
   set_kb_item(name:"SMTP/intermail", value:TRUE);
   guess = "InterMail";
   str = egrep(pattern:"InterMail ", string:banner);
   if(str) {
     str=ereg_replace(pattern:"^.*InterMail ([A-Za-z0-9\.\-]+).*$", string:str, replace:"\1");
     guess=string("InterMail version ",str);
   }
  }

  if("mail rejector" >< banner ||
      (ehlo && match(pattern:"*snubby*", string:ehlo, icase:TRUE))) {
    set_kb_item(name: "SMTP/snubby", value: TRUE);
    set_kb_item(name: "SMTP/wrapped", value: TRUE);
    guess = "Snubby Mail Rejector (not a real server)";
    log_message(port: port, data: "Verisign mail rejector appears to be running on this port.
You probably mistyped your hostname and OpenVAS is scanning the wildcard
address in the .COM or .NET domain.

Solution : enter a correct hostname");
  }

  data = string("Remote SMTP server banner :\n",  banner);
  if (guess) {
   data=string(data, "\n\n\nThis is probably: ",guess);
  }

  log_message(port:port, data:data);
  close(soc);
 }
}
