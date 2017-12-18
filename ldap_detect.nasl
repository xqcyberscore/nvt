###############################################################################
# OpenVAS Vulnerability Test
# $Id: ldap_detect.nasl 8145 2017-12-15 13:31:58Z cfischer $
#
# LDAP Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.100082");
  script_version("$Revision: 8145 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 14:31:58 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-27 12:39:47 +0100 (Fri, 27 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("LDAP Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  # LDAP Detection is currently quite fragile so keep all of those in here to catch the most common services before
  script_dependencies("find_service.nasl", "find_service1.nasl", "find_service2.nasl", "find_service_3digits.nasl");
  script_require_ports("Services/unknown", 389, 636);

  script_tag(name:"summary", value:"A LDAP Server is running at this host.

  The Lightweight Directory Access Protocol, or LDAP is an application
  protocol for querying and modifying directory services running over
  TCP/IP.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("ldap.inc");

port = get_unknown_port( default:389 );

if( ldap_alive( port:port ) ) {
  register_service( port:port, proto:"ldap" );
  set_kb_item( name:"ldap/detected", value:TRUE );
  if( is_ldapv3( port:port ) ) report = "The LDAP Server supports LDAPv3.";
  log_message( port:port, data:report );
}

exit( 0 );
