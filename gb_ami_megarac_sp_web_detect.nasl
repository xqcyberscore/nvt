###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ami_megarac_sp_web_detect.nasl 5817 2017-03-31 10:19:30Z cfi $
#
# MegaRAC SP Firmware Detection
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105383");
  script_version("$Revision: 5817 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-31 12:19:30 +0200 (Fri, 31 Mar 2017) $");
  script_tag(name:"creation_date", value:"2015-09-23 10:26:45 +0200 (Wed, 23 Sep 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("MegaRAC SP Firmware Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script performs HTTP based detection of AMI MegaRAC SP Firmware");

  script_tag(name:"insight", value:"The remote host is a MegaRAC remote management controller. MegaRAC Service Processors come
  in various formats - PCI cards, embedded modules, software-only.");

  script_xref(name:"URL", value:"http://www.ami.com/products/remote-management/service-processor/");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );

url = '/index.html';
buf = http_get_cache( item:url, port:port );

if( "Server: GoAhead-Webs" >!< buf || "<title>Megarac SP</title>" >!< buf ||
    "COPYRIGHT American Megatrends" >!< buf ) exit( 0 );

cpe = 'cpe:/o:ami:megarac_sp';

set_kb_item( name:"ami_megarac_sp/installed", value:TRUE );

register_product( cpe:cpe, location:url, port:port );

register_and_report_os( os:"MegaRAC SP", cpe:cpe, banner_type:"HTTP banner", port:port, desc:"MegaRAC SP Firmware Detection", runs_key:"unixoide" );

log_message( data: build_detection_report( app:"AMI MegaRAC SP Firmware",
                                           install:url,
                                           cpe:cpe,
                                           concluded: 'HTTP request' ),
             port:port );
exit( 0 );

