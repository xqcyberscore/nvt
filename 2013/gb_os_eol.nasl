###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_os_eol.nasl 7849 2017-11-21 14:29:21Z cfischer $
#
# OS End Of Life Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.103674");
  script_version("$Revision: 7849 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-21 15:29:21 +0100 (Tue, 21 Nov 2017) $");
  script_tag(name:"creation_date", value:"2013-03-05 18:11:24 +0100 (Tue, 05 Mar 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("OS End Of Life Detection");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("os_detection.nasl");
  script_mandatory_keys("HostDetails/OS/BestMatch");

  script_tag(name:"summary", value:"OS End Of Life Detection

  The Operating System on the remote host has reached the end of life and should
  not be used anymore");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("os_eol.inc");
include("host_details.inc");
include("misc_func.inc");

os_cpe = best_os_cpe();
if( ! os_cpe ) exit( 0 );

if( os_reached_eol( cpe:os_cpe ) ) {

  eol_url     = get_eol_url( cpe:os_cpe );
  eol_date    = get_eol_date( cpe:os_cpe );
  eol_name    = get_eol_name( cpe:os_cpe );
  eol_version = get_eol_version( cpe:os_cpe );
  version     = get_version_from_cpe( cpe:os_cpe );

  report = build_eol_message( name:eol_name,
                              cpe:os_cpe,
                              version:version,
                              eol_version:eol_version,
                              eol_date:eol_date,
                              eol_url:eol_url,
                              eol_type:"os" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
