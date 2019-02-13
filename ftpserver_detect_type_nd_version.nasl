###############################################################################
# OpenVAS Vulnerability Test
# $Id: ftpserver_detect_type_nd_version.nasl 13630 2019-02-13 11:03:59Z cfischer $
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
  script_version("$Revision: 13630 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 12:03:59 +0100 (Wed, 13 Feb 2019) $");
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

  bannerlo = tolower( banner );

  if( service_is_unknown( port:port ) )
    register_service( port:port, proto:"ftp", message:"A FTP Server seems to be running on this port." );

  help = get_ftp_cmd_banner( port:port, cmd:"HELP" );
  syst = get_ftp_cmd_banner( port:port, cmd:"SYST" );
  stat = get_ftp_cmd_banner( port:port, cmd:"STAT" );

  set_kb_item( name:"ftp/banner/available", value:TRUE );
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

  else if( "FileCOPA FTP Server" >< banner ) {
    set_kb_item( name:"ftp/intervations/filecopa/detected", value:TRUE );
    guess = "InterVations FileCOPA FTP Server";
  }

  else if( banner =~ "220[- ]+smallftpd" ) {
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

  else if( banner =~ "220[- ]FTP Server ready" ) {
    set_kb_item( name:"ftp/ftp_ready_banner/detected", value:TRUE );
    guess = "Various FTP servers like KnFTP or Schneider Electric Quantum Ethernet Module ";
  }

  else if( banner =~ "220[- ]Ready" ) {
    set_kb_item( name:"ftp/ready_banner/detected", value:TRUE );
    guess = "Various FTP servers like Janitza FTP";
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

  else if( egrep( string:banner, pattern:"FTP server.*[Vv]ersion (wu|wuftpd)-" ) ) {
    set_kb_item( name:"ftp/wu_ftpd/detected", value:TRUE );
    guess = "WU-FTPD";
  }

  else if( "WarFTPd" >< banner || "WAR-FTPD" >< banner ) {
    set_kb_item( name:"ftp/war_ftpd/detected", value:TRUE );
    guess = "WarFTPd";
  }

  else if( "I'm freeFTPd" >< banner ) {
    set_kb_item( name:"ftp/free_ftpd/detected", value:TRUE );
    guess = "freeFTPd";
  }

  else if( banner =~ "220[- ]Browser Ftp Server\." ) {
    set_kb_item( name:"ftp/browser_ftp_server_banner/detected", value:TRUE );
    guess = "Various FTP servers like MySCADA MyPRO";
  }

  else if( "Welcome to D-Link's FTP Server" >< banner ) {
    set_kb_item( name:"ftp/dlink/ftp_server/detected", value:TRUE );
    guess = "Multiple D-Link products like Central WiFiManager";
  }

  else if( "pyftpd" >< bannerlo ) {
    set_kb_item( name:"ftp/pyftpdlib/detected", value:TRUE );
    guess = "pyftpdlib";
  }

  else if( "FTP Services for ClearPath MCP" >< banner ) {
    set_kb_item( name:"ftp/clearpath/mcp/detected", value:TRUE );
    guess = "ClearPath MCP";
  }

  else if( "welcome to vibnode." >< bannerlo ) {
    set_kb_item( name:"ftp/prueftechnik/vibnode/detected", value:TRUE );
    guess = "PRUFTECHNIK VIBNODE";
  }

  else if( "Welcome to Pure-FTPd" >< banner || "Welcome to PureFTPd" >< banner || "Pure-FTPd - http://pureftpd.org" >< help ) {
    set_kb_item( name:"ftp/pure_ftpd/detected", value:TRUE );
    guess = "Pure-FTPd";
  }

  else if( "FCX STARDOM" >< banner ) {
    set_kb_item( name:"ftp/yokogawa/stardom/detected", value:TRUE );
    guess = "Yokogawa STARDOM";
  }

  else if( banner =~ "CP ([0-9\-]+) (IT )?FTP-Server V([0-9.]+) ready for new user" ) {
    set_kb_item( name:"ftp/siemens/simatic_cp/detected", value:TRUE );
    guess = "Siemens SIMATIC CP";
  }

  else if( banner =~ "220[- ]FreeFloat" || "FreeFloat Ftp Server" >< banner ) {
    set_kb_item( name:"ftp/freefloat/detected", value:TRUE );
    guess = "FreeFloat";
  }

  else if( banner =~ "220[- ]quickshare ftpd" ) {
    set_kb_item( name:"ftp/quickshare/file_share/detected", value:TRUE );
    guess = "QuickShare File Share";
  }

  else if( banner =~ "220[- ]SpoonFTP" ) {
    set_kb_item( name:"ftp/spoonftp/detected", value:TRUE );
    guess = "SpoonFTP";
  }

  else if( "Quick 'n Easy FTP Server" >< banner ) {
    set_kb_item( name:"ftp/quick_n_easy/detected", value:TRUE );
    guess = "Quick 'n Easy FTP Server";
  }

  else if( "Powerd by BigFoolCat Ftp Server" >< banner || banner =~ "220[- ]+Welcome to my ftp server" ) {
    set_kb_item( name:"ftp/easy_ftp/detected", value:TRUE );
    guess = "Easy~FTP Server";
  }

  else if( "Golden FTP Server" >< banner ) {
    set_kb_item( name:"ftp/golden_tfp/detected", value:TRUE );
    guess = "Golden FTP Server";
  }

  else if( banner =~ "220[- ]ActiveFax" ) {
    set_kb_item( name:"ftp/actfax_ftp/detected", value:TRUE );
    guess = "ActFax FTP Server";
  }

  else if( egrep( pattern:".*heck Point Firewall-1 Secure FTP.*", string:banner ) ) {
    set_kb_item( name:"ftp/fw1ftpd/detected", value:TRUE );
    register_product( cpe:"cpe:/a:checkpoint:firewall-1", location:install, port:port );
    guess = "Check Point Firewall-1";
  }

  else if( "Menasoft GrayFTP Server" >< banner ) {
    set_kb_item( name:"ftp/menasoft/sphereftp/detected", value:TRUE );
    guess = "Menasoft SphereFTP Server";
  }

  else if( banner =~ "220[- ](AXIS|Axis).*Network Camera" ) {
    set_kb_item( name:"ftp/axis/network_camera/detected", value:TRUE );
    guess = "Axis Network Camera";
  }

  else if( "ProFTPD" >< banner || "NASFTPD Turbo station" >< banner ) {
    set_kb_item( name:"ftp/proftpd/detected", value:TRUE );
    guess = "ProFTPD";
  }

  else if( banner =~ "^220[- ]bftpd " ) {
    set_kb_item( name:"ftp/bftpd/detected", value:TRUE );
    guess = "Bftpd FTP";
  }

  else if( "FileZilla Server" >< banner ) {
    set_kb_item( name:"ftp/filezilla/detected", value:TRUE );
    guess = "FileZilla";
  }

  else if( banner =~ " FTP server \(MikroTik .* ready" ) {
    set_kb_item( name:"ftp/mikrotik/detected", value:TRUE );
    guess = "MikroTik RouterOS";
  }

  else if( "Welcome on" >< banner && "Gabriel's FTP Server" >< banner ) {
    set_kb_item( name:"ftp/open-ftpd/detected", value:TRUE );
    guess = "Open-FTPD";
  }

  else if( "xlweb FTP server" >< banner ) {
    set_kb_item( name:"ftp/honeywell/falcon_xl/detected", value:TRUE );
    guess = "Honeywell Falcon XL Web Controller";
  }

  else if( banner =~ "220[- ]PCMan's FTP Server" ) {
    set_kb_item( name:"ftp/pcmans/ftp/detected", value:TRUE );
    guess = "PCMan's FTP Server";
  }

  else if( "Welcome to Seagate Central" >< banner ) {
    set_kb_item( name:"ftp/seagate/central/detected", value:TRUE );
    guess = "Seagate Central";
  }

  else if( banner =~ "220[- ]Titan FTP Server " ) {
    set_kb_item( name:"ftp/titan/ftp/detected", value:TRUE );
    guess = "Titan FTP Server";
  }

  else if( "Minftpd" >< banner ) {
    set_kb_item( name:"ftp/ftpdmin/detected", value:TRUE );
    guess = "Ftpdmin";
  }

  else if( "220 Features p a" >< banner || "Sami FTP Server" >< banner ) {
    set_kb_item( name:"ftp/samiftp/detected", value:TRUE );
    guess = "KarjaSoft Sami FTP";
  }

  else if( banner =~ "Welcome to the (Cisco TelePresence|Codian) MCU" ) {
    set_kb_item( name:"ftp/cisco/telepresence/detected", value:TRUE );
    guess = "Cisco TelePresence";
  }

  else if( egrep( pattern:".*icrosoft FTP.*", string:banner ) ) {
    set_kb_item( name:"ftp/microsoft/iis_ftp/detected", value:TRUE );
    guess = "Microsoft IIS FTP Server";
  }

  else if( "ManageUPSnet" >< banner ) {
    set_kb_item( name:"ftp/manageupsnet/detected", value:TRUE );
    guess = "ManageUPSNET FTP";
  }

  else if( "Isilon OneFS" >< banner ) {
    set_kb_item( name:"ftp/emc/isilon_onefs/detected", value:TRUE );
    guess = "EMC Isilon OneFS";
  }

  else if( "SurgeFTP" >< banner ) {
    set_kb_item( name:"ftp/surgeftp/detected", value:TRUE );
    guess = "SurgeFTP";
  }

  else if( "GuildFTPd" >< banner || "GuildFTPD FTP" >< banner ) {
    set_kb_item( name:"ftp/guildftpd/detected", value:TRUE );
    guess = "GuildFTPd";
  }

  else if( "IOS-FTP server" >< banner ) {
    set_kb_item( name:"ftp/cisco/ios_ftp/detected", value:TRUE );
    guess = "Cisco IOS FTP";
  }

  else if( "UNIVERSAL FTP SERVER" >< banner ) {
    set_kb_item( name:"ftp/teamtek/universal_ftp/detected", value:TRUE );
    guess = "Teamtek Universal FTP";
  }

  else if( "BlackJumboDog" >< banner ) {
    set_kb_item( name:"ftp/blackjumbodog/detected", value:TRUE );
    guess = "BlackJumboDog";
  }

  else if( "SunFTP " >< banner ) {
    set_kb_item( name:"ftp/sunftp/detected", value:TRUE );
    guess = "SunFTP";
  }

  else if( "EFTP " >< banner ) {
    set_kb_item( name:"ftp/eftp/detected", value:TRUE );
    guess = "EFTP";
  }

  else if( "ArGoSoft FTP Server" >< banner ) {
    set_kb_item( name:"ftp/argosoft/ftp/detected", value:TRUE );
    guess = "ArGoSoft FTP";
  }

  else if( "GlobalSCAPE Secure FTP Server" >< banner ) {
    set_kb_item( name:"ftp/globalscape/secure_ftp/detected", value:TRUE );
    guess = "GlobalSCAPE Secure FTP Server";
  }

  else if( "HP ARPA FTP" >< banner ) {
    set_kb_item( name:"ftp/hp/arpa_ftp/detected", value:TRUE );
    guess = "HP ARPA FTP / MPEi/X";
  }

  else if( egrep( pattern:".*RaidenFTPD.*", string:banner ) ) {
    set_kb_item( name:"ftp/raidenftpd/detected", value:TRUE );
    guess = "RaidenFTPD";
  }

  else if( "Serv-U FTP Server" >< banner ) {
    set_kb_item( name:"ssh_or_ftp/serv-u/detected", value:TRUE );
    set_kb_item( name:"ftp/serv-u/ftp/detected", value:TRUE );
    guess = "Serv-U FTP";
  }

  else if( "Flash FTP Server" >< banner ) {
    set_kb_item( name:"ftp/flash/ftp/detected", value:TRUE );
    guess = "Flash FTP Server";
  }

  else if( "PlatinumFTPserver" >< banner ) {
    set_kb_item( name:"ftp/platinum/ftp/detected", value:TRUE );
    guess = "Platinum FTP";
  }

  else if( egrep( pattern:"^220.*RobotFTP" ) ) {
    set_kb_item( name:"ftp/robot/ftp/detected", value:TRUE );
    guess = "RobotFTP";
  }

  else if( "220 Wing FTP Server" >< banner ) {
    set_kb_item( name:"ftp/wing/ftp/detected", value:TRUE );
    guess = "Wing FTP";
  }

  else if( "220-Complete FTP server" >< banner ) {
    set_kb_item( name:"ftp/complete/ftp/detected", value:TRUE );
    guess = "Complete FTP";
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

  # nb: From 2009/Omni_NFS_36608.nasl, pattern is currently not that detailed so keep at the bottom.
  else if( "XLINK" >< banner ) {
    set_kb_item( name:"ftp/omni-nfs/xlink/detected", value:TRUE );
    guess = "Omni-NFS XLINK";
  }

  # nb: From 2009/httpdx_35006.nasl, pattern is currently not that detailed so keep at the bottom.
  else if( "httpdx" >< banner ) {
    set_kb_item( name:"ftp/httpdx/detected", value:TRUE );
    set_kb_item( name:"www_or_ftp/httpdx/detected", value:TRUE );
    guess = "httpdx";
  }

  # nb: From sw_vsftpd_detect.nasl, pattern is currently not that detailed so keep at the bottom.
  else if( "vsftpd" >< bannerlo ) {
    set_kb_item( name:"ftp/vsftpd/detected", value:TRUE );
    guess = "vsFTPd";
  }

  # nb: From secpod_tnftpd_detect.nasl, pattern is currently not that detailed so keep at the bottom.
  else if( "tnftpd" >< banner ) {
    set_kb_item( name:"ftp/tnftpd/detected", value:TRUE );
    guess = "tnftpd";
  }

  # nb: From secpod_tnftpd_detect.nasl, pattern is currently not that detailed so keep at the bottom.
  else if( "Buffy" >< banner ) {
    set_kb_item( name:"ftp/buffy/detected", value:TRUE );
    guess = "Buffy";
  }

  report = 'Remote FTP server banner:\n\n' + banner;
  if( strlen( guess ) > 0 )
    report += '\n\nThis is probably: ' + guess;

  if( syst && egrep( pattern:"^215 .+", string:syst ) )
    report += '\n\nServer operating system information collected via "SYST" command:\n\n' + syst;

  if( stat && egrep( pattern:"^211 .+", string:stat ) )
    report += '\n\nServer status information collected via "STAT" command:\n\n' + stat;

  log_message( port:port, data:report );
}

exit( 0 );