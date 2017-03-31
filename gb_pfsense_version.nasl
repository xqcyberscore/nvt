###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pfsense_version.nasl 2664 2016-02-16 07:43:49Z antu123 $
#
# pfSense Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105328");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version ("$Revision: 2664 $");
 script_tag(name:"last_modification", value:"$Date: 2016-02-16 08:43:49 +0100 (Tue, 16 Feb 2016) $");
 script_tag(name:"creation_date", value:"2015-08-21 14:51:09 +0200 (Fri, 21 Aug 2015)");
 script_name("pfSense Detection");

 script_tag(name: "summary" , value: "This script performs SSH based detection of pfSense");

 script_tag(name:"qod_type", value:"package");

 script_summary("Checks for the presence of pfSense");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
 script_dependencies("gather-package-list.nasl");
 script_require_ports("Services/ssh", 22);
 script_mandatory_keys("pfSense/uname");
 exit(0);
}

include("host_details.inc");

uname = get_kb_item( "pfSense/uname" );
if( ! uname || "pfSense" >!< uname ) exit( 0 );

vers = 'unknown';
cpe = 'cpe:/a:pfsense:pfsense';

version = eregmatch( pattern:'Welcome to pfSense ([^-]+)-RELEASE', string:uname );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  cpe += ':' + vers;
}

set_kb_item( name:"pfsense/installed", value:TRUE );

register_product( cpe:cpe, location:'ssh' );

log_message( data: build_detection_report( app:'pfSense',
                                           version:vers,
                                           install:'ssh',
                                           cpe:cpe,
                                           concluded: version[0] ),
             port:0 );

exit( 0 );
