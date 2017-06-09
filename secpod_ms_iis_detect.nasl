###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_iis_detect.nasl 6065 2017-05-04 09:03:08Z teissa $
#
# Microsoft IIS Webserver Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900710");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 6065 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-04 11:03:08 +0200 (Thu, 04 May 2017) $");
  script_tag(name:"creation_date", value:"2009-05-20 10:26:22 +0200 (Wed, 20 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Microsoft IIS Webserver Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Service detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("IIS/banner");
  script_require_ports("Services/www", 80);
  script_tag(name : "summary" , value :"This script detects the installed MS IIS Webserver and sets the
result in KB");
  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

iisPort = get_http_port(default:80);

response = get_http_banner( port:iisPort );

if( response !~ "Server: (Microsoft-)?IIS"){
  exit(0);
}

iv = 'unknown';
iisVer = eregmatch(pattern:"IIS\/([0-9.]+)", string:response);

if( ! isnull( iisVer[1] ) ) iv = iisVer[1];

# KB for Internet Information Service (IIS)
set_kb_item(name:"IIS/" + iisPort + "/Ver", value:iv);
set_kb_item(name:"IIS/installed",value:TRUE);

## build cpe and store it as host_detail
cpe = build_cpe(value: iv, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:iis:");
if(isnull(cpe))
  cpe = 'cpe:/a:microsoft:iis';

register_product(cpe:cpe, location:iisPort + '/tcp', port:iisPort);
log_message(data: build_detection_report(app:"Microsoft IIS Webserver", version:iisVer[1], install:iisPort + '/tcp', cpe:cpe, concluded: iisVer[0]),
            port:iisPort);


