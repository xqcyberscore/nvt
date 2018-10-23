###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ftp_anonymous.nasl 12030 2018-10-23 09:41:40Z cfischer $
#
# Anonymous FTP Login Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108477");
  script_version("$Revision: 12030 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-23 11:41:40 +0200 (Tue, 23 Oct 2018) $");
  script_tag(name:"creation_date", value:"2009-03-12 10:50:11 +0100 (Thu, 12 Mar 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Anonymous FTP Login Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("FTP");
  script_dependencies("find_service2.nasl", "find_service_3digits.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);

  script_tag(name:"summary", value:"Checks if the remote FTP Server allows anonymous logins.

  Note: The reporting takes place in a separate VT 'Anonymous FTP Login Reporting' (OID: 1.3.6.1.4.1.25623.1.0.900600).");

  script_tag(name:"vuldetect", value:"Try to login with an anonymous account at the remote FTP Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");

report = 'It was possible to login to the remote FTP service with the following anonymous account(s):\n\n';
listingReport = '\nHere are the contents of the remote FTP directory listing:\n';

port = get_ftp_port( default:21 );

domain = get_kb_item( "Settings/third_party_domain" );
if( isnull( domain ) ) {
  domain = this_host_name();
}

vtstrings = get_vt_strings();

passwd = string( vtstrings["lowercase"], "@", domain );

foreach user( make_list( "anonymous", "ftp" ) ) {

  soc1 = open_sock_tcp( port );
  if( ! soc1 ) continue;

  login_details = ftp_log_in( socket:soc1, user:user, pass:passwd );
  if( ! login_details ) {
    ftp_close( socket:soc1 );
    continue;
  }

  vuln = TRUE;
  report += user + ':' + passwd + '\n';

  set_kb_item( name:"ftp/" + port + "/anonymous", value:TRUE );
  set_kb_item( name:"ftp/anonymous_ftp/detected", value:TRUE );

  if( ! get_kb_item( "ftp/login" ) ) {
    set_kb_item( name:"ftp/login", value:user );
    set_kb_item( name:"ftp/password", value:passwd );
  }

  # TODO/TBD: Some servers/firewall setups might not allow us to create
  # a PASV connection so we might need to do an Active-FTP connection
  # to get a file listing.
  port2 = ftp_get_pasv_port( socket:soc1 );
  if( ! port2 ) {
    ftp_close( socket:soc1 );
    continue;
  }

  soc2 = open_sock_tcp( port2, transport:get_port_transport( port ) );
  if( ! soc2 ) {
    ftp_close( socket:soc1 );
    continue;
  }

  send( socket:soc1, data:'LIST /\r\n' );
  listing = ftp_recv_listing( socket:soc2 );
  close( soc2 );
  ftp_close( socket:soc1 );

  if( listing && strlen( listing ) ) {
    listingAvailable = TRUE;
    listingReport += '\nAccount "' + user + '":\n\n' + listing;
  }
}

if( vuln ) {

  if( listingAvailable )
    report += listingReport;

  set_kb_item( name:"ftp/" + port + "/anonymous_report", value:report );
}

exit( 0 );