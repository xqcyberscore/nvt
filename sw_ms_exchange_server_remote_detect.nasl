###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_ms_exchange_server_remote_detect.nasl 9477 2018-04-13 11:33:30Z santu $
#
# Microsoft Exchange Server Remote Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Updated By Rajat Mishra<rajatm@secpod.com> On 2018-04-05
#
# Copyright:
# Copyright (c) 2016 SCHUTZWERK GmbH, http://www.schutzwerk.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.111085");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 9477 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-13 13:33:30 +0200 (Fri, 13 Apr 2018) $");
  script_tag(name:"creation_date", value:"2016-02-04 15:00:00 +0100 (Thu, 04 Feb 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Microsoft Exchange Server Remote Detection");
 
  script_copyright("This script is Copyright (C) 2016 SCHUTZWERK GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection"); 
  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25, 465, 587, "Services/pop3", 110, "Services/imap", 143);

  script_tag(name:"summary", value:"The script checks the SMTP/POP3/IMAP server
  banner for the presence of Microsoft Exchange Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("smtp_func.inc");
include("imap_func.inc");
include("pop3_func.inc");
include("cpe.inc");

cpe = 'cpe:/a:microsoft:exchange_server';

ports = get_kb_list( "Services/smtp" );
if( ! ports) ports = make_list( 25, 465, 587 );

foreach port ( ports ) {

  if( get_port_state( port ) ) {

    banner = get_smtp_banner( port:port );
    quit = get_kb_item( "smtp/" + port + "/quit" );
    noop = get_kb_item( "smtp/" + port + "/noop" );
    help = get_kb_item( "smtp/" + port + "/help" );
    rset = get_kb_item( "smtp/" + port + "/rset" );

    if( "Microsoft Exchange Internet Mail Service" >< banner || "NTLM LOGIN" >< banner ||
        "Microsoft SMTP MAIL" >< banner || "Microsoft ESMTP MAIL Service" >< banner ||
        "ESMTP Exchange Server" >< banner || "ESMTP Microsoft Exchange" >< banner ||
        ( ( "This server supports the following commands" >< help || "End of HELP information" >< help ) &&
            "Service closing transmission channel" >< quit && "Resetting" >< rset && "OK" >< noop ) ) {

      version = "unknown";
      ver = eregmatch( pattern:"Version: ([0-9.]+)", string:banner );
      if( ver[1] )
        version = ver[1];
      else if ( ver = eregmatch( pattern:"Service ([0-9.]+)", string:banner )){
        if( ver[1] ) version = ver[1];
      }
      else if ( ver = eregmatch( pattern:"Microsoft Exchange Server .* ([0-9.]+)", string:banner )){
      if( ver[1] ) version = ver[1];
}

      set_kb_item(name:"SMTP/microsoft_esmtp_5", value:TRUE);
      set_kb_item(name:"exchange_server/Installed", value:TRUE);      
      cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:exchange_server:");
      if(isnull(cpe))
       cpe = "cpe:/a:microsoft:exchange_server";
      register_product( cpe:cpe, location:port + '/tcp', port:port, service:"smtp");

      log_message( data: build_detection_report( app:"Microsoft Exchange",
                                                 version:version,
                                                 install:port + '/tcp',
                                                 cpe:cpe,
                                                 extra:"Service version: " + version,
                                                 concluded:banner ),
                                                 port:port );
    }
  }
}

ports = get_kb_list( "Services/imap" );
if( ! ports) ports = make_list( 143 );

foreach port ( ports ) {

  if( get_port_state( port ) ) {

    banner = get_imap_banner( port:port );
    
    if( "The Microsoft Exchange IMAP4 service is ready" >< banner ||
        "Microsoft Exchange Server" >< banner ) {
      version = "unknown";
      ver = eregmatch( pattern:"Version ([0-9.]+)", string:banner );
      if( ver[1] ) version = ver[1];

     else
    {
      ver = eregmatch( pattern:"Microsoft Exchange Server .* ([0-9.]+)", string:banner );
      if( ver[1] ) version = ver[1];
}
      set_kb_item(name:"exchange_server/Installed", value:TRUE); 
      cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:exchange_server:");
      if(isnull(cpe))
       cpe = "cpe:/a:microsoft:exchange_server";
      register_product( cpe:cpe, location:port + '/tcp', port:port, service:"imap");

      log_message( data: build_detection_report( app:"Microsoft Exchange",
                                                 install:port + '/tcp',
                                                 cpe:cpe,
                                                 extra:"Service version: " + version,
                                                 concluded:banner ),
                                                 port:port );
    }
  }
}

port = get_kb_item( "Services/pop3" );
if( ! port ) port = 110;

if( get_port_state( port ) ) {

  banner = get_pop3_banner( port:port );
  
  if( "Microsoft Windows POP3 Service Version" >< banner ||
      "The Microsoft Exchange POP3 service is ready." >< banner ||
      "Microsoft Exchange Server" >< banner ||
      "Microsoft Exchange POP3-Server" >< banner ) {

    version = "unknown";
    ver = eregmatch( pattern:"Version ([0-9.]+)", string:banner );
    if( ver[1] ){
     version = ver[1];
    }
    else
    {
      ver = eregmatch( pattern:"Microsoft Exchange Server .* ([0-9.]+)", string:banner );
      if( ver[1] ){
        version = ver[1];
    }
}
    set_kb_item(name:"exchange_server/Installed", value:TRUE); 
    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:exchange_server:");
    if(isnull(cpe))
      cpe = "cpe:/a:microsoft:exchange_server";
    register_product( cpe:cpe, location:port + '/tcp', port:port, service:"pop3");
    log_message( data: build_detection_report( app:"Microsoft Exchange",
                                               install:port + '/tcp',
                                               cpe:cpe,
                                               extra:"Service version: " + version,
                                               concluded:banner ),
                                               port:port );
  }
}

exit(0);