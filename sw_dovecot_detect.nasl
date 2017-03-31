###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_dovecot_detect.nasl 2837 2016-03-11 09:19:51Z benallard $
#
# Dovecot POP3/IMAP Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111031");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 2837 $");
  script_tag(name:"last_modification", value:"$Date: 2016-03-11 10:19:51 +0100 (Fri, 11 Mar 2016) $");
  script_tag(name:"creation_date", value:"2015-08-26 12:00:00 +0200 (Wed, 26 Aug 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Dovecot POP3/IMAP Detection");
 
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_summary("Checks for the presence of Dovecot");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection"); 
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/imap", 143, "Services/pop3", 110);

  script_tag(name : "summary" , value : "The script checks the POP3/IMAP server
  banner for the presence of Dovecot.");

  script_tag(name:"qod_type", value:"remote_banner");

 exit(0);
}

include("host_details.inc");
include("pop3_func.inc");
include("imap_func.inc");

cpe = 'cpe:/a:dovecot:dovecot';
pattern = "Dovecot ([a-zA-Z()]+ )?ready";

ports = get_kb_list( "Services/imap" );
if( ! ports) ports = make_list( 143 );

foreach port ( ports ) {

  if( get_port_state( port ) ) {

    banner = get_imap_banner( port:port );

    if( egrep( pattern:pattern, string:banner, icase:1 ) ) {
      register_product( cpe:cpe, location:port + '/tcp', port:port );

      log_message( data: build_detection_report( app:"Dovecot",
                                                     install:port + '/tcp',
                                                     cpe:cpe,
                                                     concluded:banner ),
                                                     port:port );
    }
  }
}

port = get_kb_item( "Services/pop3" );
if( ! port ) port = 110;

if( get_port_state( port ) ) {

  banner = get_pop3_banner( port:port );

  if( egrep( pattern:pattern, string:banner, icase:1 ) ) {
    register_product( cpe:cpe, location:port + '/tcp', port:port );

    log_message( data: build_detection_report( app:"Dovecot",
                                                   install:port + '/tcp',
                                                   cpe:cpe,
                                                   concluded:banner ),
                                                   port:port );
  }
}

exit( 0 );
