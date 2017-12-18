###############################################################################
# OpenVAS Vulnerability Test
# $Id: sendmail_expn.nasl 8147 2017-12-15 13:51:17Z cfischer $
#
# Check if Mailserver answer to VRFY and EXPN requests
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100072");
  script_version("$Revision: 8147 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 14:51:17 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-23 19:32:33 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Check if Mailserver answer to VRFY and EXPN requests");  
  script_category(ACT_GATHER_INFO);
  script_family("SMTP problems");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25, 465, 587);
  script_exclude_keys("SMTP/wrapped");

  script_xref(name:"URL", value:"http://cr.yp.to/smtp/vrfy.html");

  script_tag(name:"solution", value:"Disable VRFY and/or EXPN on your Mailserver.
  For postfix add 'disable_vrfy_command=yes' in 'main.cf'.
  For Sendmail add the option 'O PrivacyOptions=goaway'.");

  script_tag(name:"summary", value:"The Mailserver on this host answers to VRFY and/or EXPN requests.
  VRFY and EXPN ask the server for information about an address. They are inherently unusable through
  firewalls, gateways, mail exchangers for part-time hosts, etc. OpenVAS suggests that, if you really
  want to publish this type of information, you use a mechanism that legitimate users actually know
  about, such as Finger or HTTP.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("smtp_func.inc");

port = get_smtp_port( default:25 );
soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

bannertxt = smtp_recv_banner( socket:soc );
send( socket:soc, data:string("EHLO ",this_host(),"\r\n"));
ehlotxt = smtp_recv_line( socket:soc );

if( "250" >< ehlotxt || "550" >< ehlotxt ) {

  #VRFY
  send( socket: soc, data:string("VRFY root\r\n"));
  vrfy_txt = smtp_recv_line( socket:soc );

  if( "250" >< vrfy_txt || "251" >< vrfy_txt || "550" >< vrfy_txt || "252" >< vrfy_txt ) {
    if( "Administrative prohibition" >!< vrfy_txt &&
        "Access Denied" >!< vrfy_txt &&
        "not available" >!< vrfy_txt &&
        "String does not match anything" >!< vrfy_txt &&
        "Cannot VRFY user" >!< vrfy_txt &&
        "VRFY disabled" >!< vrfy_txt &&
        "252 send some mail, i'll try my best" >!< vrfy_txt ) {
      rand = 'openvas' + rand() + '\r\n';
      send( socket:soc, data:string("VRFY "+rand));
      vrfy_txt2 = smtp_recv_line( socket:soc );
      if( "252" >!< vrfy_txt2 ) {
        set_kb_item( name:"SMTP/vrfy", value:TRUE );
        VULN = TRUE;
        report += string("'VRFY root' produces the following answer: ", vrfy_txt, "\n");
      }
    }
  }

  #EXPN
  send( socket:soc, data:string("EXPN root\r\n"));
  expn_txt = smtp_recv_line( socket:soc );

  if( "250" >< expn_txt || "550" >< expn_txt ) {
    if( "Administrative prohibition" >!< expn_txt &&
        "Access Denied" >!< expn_txt &&
        "EXPN not available" >!< expn_txt &&
        "lists are confidential" >!< expn_txt &&
        "EXPN command has been disabled" >!< expn_txt && # https://msg.wikidoc.info/index.php/DISABLE_EXPAND
        "not available" >!< expn_txt ) {
      set_kb_item( name:"SMTP/expn", value:TRUE );
      VULN = TRUE;
      report += string("'EXPN root' produces the following answer: ", expn_txt, "\n");
    }
  }
}

close( soc );

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
