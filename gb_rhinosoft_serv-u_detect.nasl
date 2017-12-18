###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rhinosoft_serv-u_detect.nasl 8146 2017-12-15 13:40:59Z cfischer $
#
# Rhino Software Serv-U SSH and FTP Server Version Detection (Remote)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801117");
  script_version("$Revision: 8146 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 14:40:59 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-10-20 14:26:56 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Rhino Software Serv-U SSH and FTP Server Version Detection (Remote)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "find_service_3digits.nasl", "ftpserver_detect_type_nd_version.nasl", "ssh_detect.nasl");
  script_require_ports("Services/ftp", 21, "Services/ssh", 22);

  script_tag(name:"summary", value:"This script detects the installed version of Rhino Software
  Serv-U and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

ftpPorts = get_kb_list( "Services/ftp" );
if( ! ftpPorts ) ftpPorts = make_list( 21 );

foreach port( ftpPorts ) {

  if( get_port_state( port ) ) {

    banner = get_ftp_banner( port:port );
    if( ! banner ) continue;

    if( "Serv-U" >< banner ) {

      vers = "unknown";
      set_kb_item( name:"Serv-U/FTP/installed", value:TRUE );
      install = port + '/tcp';

      version = eregmatch( pattern:"Serv-U FTP Server v([0-9.]+)", string:banner );
      if( ! isnull( version[1] ) ) {
        vers = version[1];
        set_kb_item( name:"Serv-U/FTP/Ver", value:vers );
        set_kb_item( name:"ftp/" + port + "/Serv-U", value:vers );
      } else {
        # Response to CSID command (See get_ftp_banner() in ftp_func.inc)
        version = eregmatch( string:banner, pattern:"Name=Serv-U; Version=([^;]+);" );
        if( ! isnull( version[1] ) ) {
          vers = version[1];
          set_kb_item( name:"Serv-U/FTP/Ver", value:vers );
          set_kb_item( name:"ftp/" + port + "/Serv-U", value:vers );
        }
      }
      ## build cpe and store it as host_detail
      cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:rhinosoft:serv-u:" );
      if( isnull( cpe ) )
        cpe = 'cpe:/a:rhinosoft:serv-u';

      register_product( cpe:cpe, location:install, port:port, service:"ftp" );

      log_message( data:build_detection_report( app:"Rhino Software Serv-U FTP Server",
                                                version:vers,
                                                install:install,
                                                cpe:cpe,
                                                concluded:version[0] ),
                                                port:port );
    }
  }
}

sshPort = get_ssh_port( default:22 );
banner = get_kb_item( "SSH/banner/" + sshPort );

if( banner && "serv-u" >< tolower( banner ) ) {

  vers = "unknown";
  set_kb_item( name:"Serv-U/SSH/installed", value:TRUE );
  install = sshPort + '/tcp';

  version = eregmatch( pattern:"Serv-U_([0-9.]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    vers = version[1];
    set_kb_item( name:"Serv-U/SSH/Ver", value:vers );
    set_kb_item( name:"ssh/" + sshPort + "/Serv-U", value:vers );
  }

  ## build cpe and store it as host_detail
  cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:rhinosoft:serv-u:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:rhinosoft:serv-u';

  register_product( cpe:cpe, location:install, port:sshPort, service:"ssh" );

  log_message( data:build_detection_report( app:"Rhino Software Serv-U SSH Server",
                                            version:vers,
                                            install:install,
                                            cpe:cpe,
                                            concluded:version[0] ),
                                            port:sshPort );
}

exit( 0 );