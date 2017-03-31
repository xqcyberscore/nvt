###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_starttls_ldap.nasl 5184 2017-02-03 08:18:36Z cfi $
#
# LDAP STARTTLS Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105016");
  script_version("$Revision: 5184 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-03 09:18:36 +0100 (Fri, 03 Feb 2017) $");
  script_tag(name:"creation_date", value:"2014-04-25 15:18:02 +0100 (Fri, 25 Apr 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("LDAP STARTTLS Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389);
  script_mandatory_keys("ldap/detected");

  script_tag(name:"summary", value:"The remote LDAP Server supports STARTTLS.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("ldap.inc");

port = get_ldap_port( default:389 );

if( get_port_transport( port ) > ENCAPS_IP ) exit( 0 );

if( ldap_starttls_supported( port:port ) ) {
  set_kb_item( name:"ldap/" + port + "/starttls", value:TRUE );
  set_kb_item( name:"starttls_typ/" + port, value:"ldap" );
  log_message( port:port );
}

exit( 0 );
