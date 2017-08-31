###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_axis_network_cameras_ftp_detect.nasl 6938 2017-08-16 11:10:00Z santu $
#
# Axis Camera Detection (FTP)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.810933");
 script_version ("$Revision: 6938 $");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"last_modification", value:"$Date: 2017-08-16 13:10:00 +0200 (Wed, 16 Aug 2017) $");
 script_tag(name:"creation_date", value:"2017-04-20 13:57:40 +0530 (Thu, 20 Apr 2017)");
 script_tag(name:"qod_type", value:"remote_banner");
 script_name("Axis Camera Detection (FTP)");

 script_tag(name: "summary" , value: "Detection of Axis Camera.

 This script performs FTP based detection of Axis Camera.");

 script_category(ACT_GATHER_INFO);
 script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
 script_family("Product detection");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}


include("cpe.inc");
include("ftp_func.inc");
include("host_details.inc");

## Variable initialization
version = 'unknown';
axport = 0;
banner = "";

## Get port
if(!axport = get_ftp_port( default:21 )) exit(0);

## Get banner
if(!banner = get_ftp_banner(port:axport)) exit(0);

## Confirm device
if(banner !~ "220 (AXIS|Axis).*Network Camera") exit( 0 );

set_kb_item( name:"axis/camera/installed", value:TRUE );

## Grep for version
v = eregmatch( pattern:'Network Camera ([0-9.]+)', string:banner );
if(v[1])
{
  version = v[1];
  set_kb_item(name:"axis/camera/version", value:version);
}

## build cpe and store it as host_detail
cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:axis:network_camera:");
if(isnull(cpe)){
  cpe = "cpe:/a:axis:network_camera";
}

## Grep for model
m = eregmatch(pattern:'220 (AXIS|Axis) ([A-Z0-9.]+)', string:banner);
if(m[2])
{
  model = m[2];
  set_kb_item(name:"axis/camera/model", value:m[2]);
}

## Register product
register_product(cpe:cpe, location:axport + '/tcp', port:axport, service:"ftp");

log_message(data: build_detection_report(app:"Axis Camera " + model,
                                         version:version,
                                         install:axport + '/tcp',
                                         cpe:cpe,
                                         concluded:version));
exit(0);
