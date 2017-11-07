###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_mariadb_os_detection.nasl 7669 2017-11-06 15:08:30Z cfischer $
#
# MySQL/MariaDB Server OS Identification
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108192");
  script_version("$Revision: 7669 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-06 16:08:30 +0100 (Mon, 06 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-07-17 09:13:48 +0100 (Mon, 17 Jul 2017)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("MySQL/MariaDB Server OS Identification");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("mysql_version.nasl");
  script_mandatory_keys("MySQL_MariaDB/installed");

  script_tag(name:"summary", value:"This script performs MySQL/MariaDB server banner based OS detection.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");

SCRIPT_DESC = "MySQL/MariaDB Server OS Identification";
BANNER_TYPE = "MySQL/MariaDB server banner";

cpe_list = make_list( "cpe:/a:mysql:mysql", "cpe:/a:oracle:mysql", "cpe:/a:mariadb:mariadb" );

if( ! infos = get_all_app_port_from_list( cpe_list:cpe_list ) ) exit( 0 );
port = infos['port'];

if( ! banner = get_kb_item( "mysql_mariadb/full_banner/" + port ) ) exit( 0 );

if( "ubuntu" >< banner ) {
  if( "ubuntu0.14.04" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"14.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "ubuntu0.16.04" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"16.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "ubuntu0.17.04" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"17.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "ubuntu0.17.10" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"17.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

if( "+deb" >< banner || "~jessie" >< banner || "~wheezy" >< banner || "~stretch" >< banner ||
    "squeeze" >< banner || "lenny" >< banner || # squeeze has .squeeze or ~squeeze versions, lenny as well
    "~bpo" >< banner ) { # Banners for debian backports like 5.6.30-1~bpo8+1-log

  # nb: The order matters in case of backports which might have something like +deb9~bpo8
  if( "lenny" >< banner ) {
    register_and_report_os( os:"Debian GNU/Linux", version:"5.0", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "squeeze" >< banner ) {
    register_and_report_os( os:"Debian GNU/Linux", version:"6.0", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  # nb: Starting with Wheezy (7.x) we have minor releases within the version so we don't use an exact version like 7.0 as we can't differ between the OS in the banner here
  } else if( "~wheezy" >< banner || "~bpo7" >< banner ) {
    register_and_report_os( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "+deb8" >< banner || "~jessie" >< banner || "~bpo8" >< banner ) {
    register_and_report_os( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "+deb9" >< banner || "~stretch" >< banner || "~bpo9" >< banner ) {
    register_and_report_os( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

register_unknown_os_banner( banner:banner, banner_type_name:BANNER_TYPE, banner_type_short:"mysql_mariadb_banner", port:port );
exit( 0 );
