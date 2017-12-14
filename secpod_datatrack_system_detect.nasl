###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_datatrack_system_detect.nasl 8087 2017-12-12 13:12:04Z teissa $
#
# DataTrack System Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_summary = "This script finds the installed DataTrack System version and saves
  the result in KB.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902061");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 8087 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-12 14:12:04 +0100 (Tue, 12 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("DataTrack System Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Service detection");
  script_require_ports("Services/www", 81);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902061";
SCRIPT_DESC = "DataTrack System Version Detection";

dtsPort = get_http_port(default:81);
if(!dtsPort){
  exit(0);
}

banner = get_http_banner(port:dtsPort);

## Confirm the application
if("Server: MagnoWare" >< banner || ">DataTrack Web Client<" >< banner)
{
  ## Grep for the version
  dtsVer = eregmatch(pattern:"MagnoWare/([0-9.]+)", string:banner);
  if(dtsVer[1] != NULL)
  {
    ## Set the KB value
    set_kb_item(name:"www/" + dtsPort + "/DataTrack_System", value:dtsVer[1]);
    log_message(data:"DataTrack System version " + dtsVer[1] +
                                       " was detected on the host");
  
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:dtsVer[1], exp:"^([0-9.]+)", base:"cpe:/a:magnoware:datatrack_system:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}
