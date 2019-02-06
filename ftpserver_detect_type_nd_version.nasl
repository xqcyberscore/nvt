###############################################################################
# OpenVAS Vulnerability Test
# $Id: ftpserver_detect_type_nd_version.nasl 13497 2019-02-06 10:45:54Z cfischer $
#
# FTP Banner Detection
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10092");
  script_version("$Revision: 13497 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 11:45:54 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("FTP Banner Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 1999 SecuriTeam");
  script_family("Product detection");
  # nb: get_ftp_banner() is using a FTP command internally which requires a
  # successful login so the secpod_ftp_anonymous.nasl is expected to be
  # in here. This dependency also pulls in the logins.nasl.
  script_dependencies("find_service2.nasl", "find_service_3digits.nasl",
                      "ftpd_no_cmd.nasl", "secpod_ftp_anonymous.nasl");
  script_require_ports("Services/ftp", 21, 990);

  script_tag(name:"summary", value:"This Plugin detects and reports a FTP Server Banner.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");
include("misc_func.inc");

ports = ftp_get_ports();
foreach port( ports ) {

  # nb: get_ftp_banner() is verifying the received data via ftp_verify_banner() and will
  # return NULL/FALSE if we haven't received a FTP banner.
  banner = get_ftp_banner( port:port );
  if( ! banner )
    continue;

  if( service_is_unknown( port:port ) )
    register_service( port:port, proto:"ftp", message:"A FTP Server seems to be running on this port." );

  set_kb_item( name:"ftp_banner/available", value:TRUE );
  install = port + "/tcp";

  if( "NcFTPd" >< banner ) {
    set_kb_item( name:"ftp/ncftpd/detected", value:TRUE );
    register_product( cpe:"cpe:/a:ncftpd:ftp_server", location:install, port:port );
    guess = "NcFTPd";
  }

  else if( "FtpXQ FTP" >< banner ) {
    set_kb_item( name:"ftp/ftpxq/detected", value:TRUE );
    guess = "FtpXQ FTP";
  }

  else if( "Cerberus FTP" >< banner ) {
    set_kb_item( name:"ftp/cerberus/detected", value:TRUE );
    guess = "Cerberus FTP";
  }

  else if( "Home Ftp Server" >< banner ) {
    set_kb_item( name:"ftp/home_ftp/detected", value:TRUE );
    guess = "Home FTP Server";
  }

  else if( "Welcome to DXM's FTP Server" >< banner ) {
    set_kb_item( name:"ftp/xm_easy_personal/detected", value:TRUE );
    guess = "XM Easy Personal FTP Server";
  }

  else if( "VicFTPS" >< banner ) {
    set_kb_item( name:"ftp/vicftps/detected", value:TRUE );
    guess = "VicFTPS";
  }

  else if( "Core FTP Server" >< banner ) {
    set_kb_item( name:"ftp/core_ftp/detected", value:TRUE );
    guess = "Core FTP";
  }

  else if( "Femitter FTP Server ready." >< banner ) {
    set_kb_item( name:"ftp/femitter_ftp/detected", value:TRUE );
    guess = "Femitter FTP Server";
  }

  else if( "InterVations FileCOPA FTP Server" >< banner ) {
    set_kb_item( name:"ftp/intervations/filecopa/detected", value:TRUE );
    guess = "InterVations FileCOPA FTP Server";
  }

  else if( "smallftpd" >< banner ) {
    set_kb_item( name:"ftp/smallftpd/detected", value:TRUE );
    guess = "Small FTPD Server";
  }

  else if( "TYPSoft FTP Server" >< banner ) {
    set_kb_item( name:"ftp/typsoft/detected", value:TRUE );
    guess = "TYPSoft FTP Server";
  }

  else if( "DSC ftpd" >< banner ) {
    set_kb_item( name:"ftp/ricoh/dsc_ftpd/detected", value:TRUE );
    guess = "Ricoh DC Software FTP Server";
  }

  else if( "Telnet-Ftp Server" >< banner ) {
    set_kb_item( name:"ftp/telnet_ftp/detected", value:TRUE );
    guess = "Telnet-FTP Server";
  }

  else if( "220 FTP Server ready." >< banner ) {
    set_kb_item( name:"ftp/ftp_ready_banner/detected", value:TRUE );
    guess = "Various FTP servers like KnFTP";
  }

  else if( "TurboFTP Server" >< banner ) {
    set_kb_item( name:"ftp/turboftp/detected", value:TRUE );
    guess = "TurboFTP Server";
  }

  else if( "BlackMoon FTP Server" >< banner ) {
    set_kb_item( name:"ftp/blackmoon/detected", value:TRUE );
    guess = "BlackMoon FTP";
  }

  else if( "Solar FTP Server" >< banner ) {
    set_kb_item( name:"ftp/solarftp/detected", value:TRUE );
    guess = "Solar FTP";
  }

  else if( "WS_FTP Server" >< banner ) {
    set_kb_item( name:"ftp/ws_ftp/detected", value:TRUE );
    guess = "WS_FTP Server";
  }

  else if( "FTP Utility FTP server" >< banner ) {
    set_kb_item( name:"ftp/konica/ftp_utility/detected", value:TRUE );
    guess = "Konica Minolta FTP Utility";
  }

  else if( "BisonWare BisonFTP server" >< banner ) {
    set_kb_item( name:"ftp/bisonware/bisonftp/detected", value:TRUE );
    guess = "BisonWare BisonFTP Server";
  }

  else if( "Welcome to ColoradoFTP" >< banner && "www.coldcore.com" >< banner ) {
    set_kb_item( name:"ftp/coldcore/coloradoftp/detected", value:TRUE );
    guess = "ColoradoFTP";
  }

  else if( "FRITZ!Box" >< banner && "FTP server ready." >< banner ) {
    set_kb_item( name:"ftp/avm/fritzbox_ftp/detected", value:TRUE );
    guess = "AVM FRITZ!Box FTP";
  }

  else if( egrep( pattern:".*heck Point Firewall-1 Secure FTP.*", string:banner ) ) {
    set_kb_item( name:"ftp/fw1ftpd/detected", value:TRUE );
    register_product( cpe:"cpe:/a:checkpoint:firewall-1", location:install, port:port );
    guess = "Check Point Firewall-1";
  }

  # 220 VxWorks FTP server (VxWorks 5.3.1 - Secure NetLinx version (1.0)) ready.
  # 220 VxWorks (VxWorks5.4.2) FTP server ready
  # 220 VxWorks (5.4) FTP server ready
  # 220 VxWorks FTP server (VxWorks VxWorks5.5.1) ready.
  # 220 Tornado-vxWorks (VxWorks5.5.1) FTP server ready
  # 220 $hostname FTP server (VxWorks 6.4) ready.
  # 220 VxWorks (VxWorks 6.3) FTP server ready
  # 220 Tornado-vxWorks FTP server ready
  # TODO: Move into own Detection-NVT. The OS part via of VxWorks is already done in gb_ftp_os_detection.nasl
  else if( banner =~ "[vV]xWorks" && "FTP server" >< banner ) {
    set_kb_item( name:"ftp/vxftpd/detected", value:TRUE );
    register_product( cpe:"cpe:/o:windriver:vxworks", location:install, port:port );
    guess = "VxWorks FTP";
  }

  report = 'Remote FTP server banner:\n\n' + banner;
  if( strlen( guess ) > 0 )
    report += '\n\nThis is probably: ' + guess;

  log_message( port:port, data:report );
}

exit( 0 );