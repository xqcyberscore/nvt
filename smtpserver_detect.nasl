###############################################################################
# OpenVAS Vulnerability Test
# $Id: smtpserver_detect.nasl 13179 2019-01-21 08:51:36Z cfischer $
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
  script_version("$Revision: 13179 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-21 09:51:36 +0100 (Mon, 21 Jan 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SMTP Server type and version");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 1999 SecuriTeam");
  script_family("Service detection");
  script_dependencies("find_service_3digits.nasl", "check_smtp_helo.nasl");
  script_require_ports("Services/smtp", 25, 465, 587);

  script_tag(name:"summary", value:"This detects the SMTP Server's type and version by connecting to
  the server and processing the buffer received.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("smtp_func.inc");
include("host_details.inc");

ports = smtp_get_ports();

foreach port( ports ) {

  soc = open_sock_tcp( port );
  if( ! soc )
    continue;

  banner = smtp_recv_banner( socket:soc );
  banner = chomp( banner );
  if( ! banner ) {
    close( soc );
    smtp_set_is_marked_wrapped( port:port );
    continue;
  }

  if( banner !~ "^[0-9]{3}[ -].+" ) {
    close( soc );
    # Doesn't look like SMTP...
    smtp_set_is_marked_broken( port:port );
    continue;
  }

  set_kb_item( name:"smtp/banner/available", value:TRUE );

  send( socket:soc, data:'EHLO ' + smtp_get_helo_from_kb( port:port ) + '\r\n' );
  ehlo = smtp_recv_line( socket:soc );
  if( ehlo ) {

    if( get_port_transport( port ) > ENCAPS_IP )
      is_tls_ehlo = TRUE;
    else
      is_tls_ehlo = FALSE;

    set_kb_item( name:"smtp/" + port + "/ehlo", value:ehlo );

    # nb: Don't check for the status code in smtp_recv_line above as we want
    # to catch every possible response in the KB key above.
    if( ehlo =~ "^250[ -].+" ) {
      ehlo_report = "The remote SMTP server is announcing the following available ESMTP commands (EHLO response) via an ";
      if( is_tls_ehlo )
        ehlo_report += "encrypted";
      else
        ehlo_report += "unencrypted";
      ehlo_report += ' connection:\n' + chomp( ehlo );
    }

    if( auth_string = egrep( string:ehlo, pattern:"^250[ -]AUTH .+" ) ) {

      set_kb_item( name:"smtp/auth_methods/available", value:TRUE );
      auth_string = chomp( auth_string );
      auth_string = substr( auth_string, 9 );
      auths = split( auth_string, sep:" ", keep:FALSE );
      foreach auth( auths ) {
        if( is_tls_ehlo )
          set_kb_item( name:"smtp/" + port + "/tls_auth_methods", value:auth );
        else
          set_kb_item( name:"smtp/" + port + "/auth_methods", value:auth );
      }
    }
  }

  send( socket:soc, data:'HELP\r\n' );
  help = smtp_recv_line( socket:soc );
  if( help )
    set_kb_item( name:"smtp/" + port + "/help", value:help );

  send( socket:soc, data:'NOOP\r\n' );
  noop = smtp_recv_line( socket:soc );
  if( noop )
    set_kb_item( name:"smtp/" + port + "/noop", value:noop );

  send( socket:soc, data:'RSET\r\n' );
  rset = smtp_recv_line( socket:soc );
  if( rset )
    set_kb_item( name:"smtp/" + port + "/rset", value:rset );

  send( socket:soc, data:'QUIT\r\n' );
  quit = smtp_recv_line( socket:soc );
  if( quit )
    set_kb_item( name:"smtp/" + port + "/quit", value:quit );

  # nb: Don't use smtp_close() as we want to get the QUIT banner above.
  close( soc );

  if( "qmail" >< banner || "qmail" >< help ) {
    set_kb_item( name:"smtp/qmail", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/qmail", value:TRUE );
    guess = "Qmail";
  }

  else if( "XMail " >< banner ) {
    set_kb_item( name:"smtp/xmail/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/xmail", value:TRUE );
    guess = "XMail";
  }

  else if( egrep( pattern:".*nbx.*Service ready.*", string:banner ) ) {
    set_kb_item( name:"smtp/3comnbx", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/3comnbx", value:TRUE );
    guess = "3comnbx";
  }

  else if( "ZMailer Server" >< banner ||
           ( "This mail-server is at Yoyodyne Propulsion Inc." >< help && # Default help text.
             "Out" >< quit && "zmhacks@nic.funet.fi" >< help ) ) {
    set_kb_item( name:"smtp/zmailer", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/zmailer", value:TRUE );
    guess = "ZMailer";
    str = egrep( pattern:" ZMailer ", string:banner );
    if( str ) {
      str = ereg_replace( pattern:"^.*ZMailer Server ([0-9a-z\.\-]+) .*$", string:str, replace:"\1" );
      guess = string( "ZMailer version ", str );
    }
  }

  else if( "CheckPoint FireWall-1" >< banner ) {
    set_kb_item( name:"smtp/firewall-1", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/firewall-1", value:TRUE );
    guess = "CheckPoint FireWall-1";
  }

  else if( "InterMail" >< banner ||
           ( "This SMTP server is a part of the InterMail E-mail system" >< help &&
             "Ok resetting state." >< rset && "ESMTP server closing connection." >< quit ) ) {
    set_kb_item( name:"smtp/intermail", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/intermail", value:TRUE );
    guess = "InterMail";
    str = egrep( pattern:"InterMail ", string:banner );
    if( str ) {
      str = ereg_replace( pattern:"^.*InterMail ([A-Za-z0-9\.\-]+).*$", string:str, replace:"\1" );
      guess = string( "InterMail version ", str );
    }
  }

  else if( "mail rejector" >< banner ||
           ( ehlo && match( pattern:"*snubby*", string:ehlo, icase:TRUE ) ) ) {
    set_kb_item( name:"smtp/snubby", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/snubby", value:TRUE );
    smtp_set_is_marked_wrapped( port:port );
    guess   = "Snubby Mail Rejector (not a real SMTP server)";
    report  = "Verisign mail rejector appears to be running on this port. You probably mistyped your hostname and the scanner is scanning the wildcard address in the .COM or .NET domain.";
    report += '\n\nSolution: enter a correct hostname';
    log_message( port:port, data:report );
  }

  else if( egrep( pattern:"Mail(Enable| Enable SMTP) Service", string:banner ) ) {
    set_kb_item( name:"smtp/mailenable", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/mailenable", value:TRUE );
    guess = "MailEnable SMTP";
  }

  else if( " MDaemon " >< banner ) {
    set_kb_item( name:"smtp/mdaemon", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/mdaemon", value:TRUE );
    guess = "MDaemon SMTP";
  }

  else if( " InetServer " >< banner ) {
    set_kb_item( name:"smtp/inetserver/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/inetserver", value:TRUE );
    guess = "A-V Tronics InetServ SMTP";
  }

  else if( "Quick 'n Easy Mail Server" >< banner ) {
    set_kb_item( name:"smtp/quickneasy/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/quickneasy", value:TRUE );
    guess = "Quick 'n Easy Mail Server";
  }

  else if( "QK SMTP Server" >< banner ) {
    set_kb_item( name:"smtp/qk_smtp/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/qk_smtp", value:TRUE );
    guess = "QK SMTP Server";
  }

  data = string( "Remote SMTP server banner:\n", banner );
  if( strlen( guess ) > 0 )
    data = string( data, "\n\nThis is probably: ", guess );

  if( strlen( ehlo_report ) > 0 )
    data = string( data, "\n\n", ehlo_report );

  log_message( port:port, data:data );
}

exit( 0 );