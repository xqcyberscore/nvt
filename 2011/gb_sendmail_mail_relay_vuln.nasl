###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sendmail_mail_relay_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# SendMail Mail Relay Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802194");
  script_version("$Revision: 11997 $");
  script_cve_id("CVE-2002-1278", "CVE-2003-0285");
  script_bugtraq_id(6118, 7580);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-15 12:51:12 +0530 (Tue, 15 Nov 2011)");
  script_name("SendMail Mail Relay Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("SMTP problems");
  script_dependencies("smtpserver_detect.nasl", "sendmail_expn.nasl", "smtp_settings.nasl");
  script_require_ports("Services/smtp", 25);

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/10554");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6118/solution");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to send email messages outside
  of the served network. This could result in unauthorized messages being sent from the vulnerable server.");
  script_tag(name:"affected", value:"Linuxconf versions 1.24 r2, 1.2.5 r3
  Linuxconf versions 1.24 r2, 1.2.5 r3 on Conectiva Linux 6.0 through 8
  IBM AIX versions 4.3, 4.3.1, 4.3.2, 4.3.3, 5.1, 5.1 L, 5.2");
  script_tag(name:"insight", value:"The flaw is due to an error in the mailconf module in Linuxconf which
  generates the Sendmail configuration file (sendmail.cf) and configures Sendmail to run as an open mail
  relay, which allows remote attackers to send Spam email.");
  script_tag(name:"summary", value:"This host is installed with SendMail and is prone to mail relay
  vulnerability.");
  script_tag(name:"solution", value:"Upgrade to the latest version of Linuxconf version 1.29r1 or later  For IBM AIX, apply the patch from below link
  ftp://aix.software.ibm.com/aix/efixes/security/sendmail_3_mod.tar.Z");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.solucorp.qc.ca/linuxconf/");
  exit(0);
}

include("smtp_func.inc");
include("misc_func.inc");
include("network_func.inc");

port = get_smtp_port( default:25 );

banner = get_smtp_banner( port:port );
if( ! banner || "Sendmail" >!< banner ) {
  exit( 0 );
}

domain = get_kb_item( "Settings/third_party_domain" );
if( ! domain ) {
  domain = 'example.com';
}

soc = smtp_open( port:port, helo:NULL );
if( ! soc ) {
  exit( 0 );
}

src_name = this_host_name();
FROM = string( 'openvas@', src_name );
TO = string( 'openvas@', domain );

send( socket:soc, data:strcat( 'EHLO ', src_name, '\r\n' ) );
ans = smtp_recv_line( socket:soc );
if( "250" >!< ans ) {
  exit( 0 );
}

mail_from = strcat( 'MAIL FROM: <', FROM , '>\r\n' );

send( socket:soc, data:mail_from );
recv = smtp_recv_line( socket:soc );

if( ! recv || recv =~ '^5[0-9][0-9]' ) {
  exit( 0 );
}

mail_to = strcat( 'RCPT TO: <', TO , '>\r\n' );
send( socket:soc, data:mail_to );

recv = smtp_recv_line( socket:soc );

if( recv =~ '^2[0-9][0-9]' ) {

  data = string( "data\r\n" );
  send( socket:soc, data:data );
  data_rcv = smtp_recv_line( socket:soc );

  if( egrep( pattern:"3[0-9][0-9]", string:data_rcv ) ) {

    send( socket:soc, data:string( "OpenVAS-Relay-Test\r\n.\r\n" ) );
    mail_send = smtp_recv_line( socket:soc );

    if( "250" >< mail_send ) {
      security_message( port:port );
      smtp_close( socket:soc );
      exit( 0 );
    }
  }
}
smtp_close( socket:soc );

exit( 99 );
