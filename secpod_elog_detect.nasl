###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_elog_detect.nasl 8168 2017-12-19 07:30:15Z teissa $
#
# ELOG Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "This script finds the running ELOG Version and saves the
  result in KB.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901008");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 8168 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 08:30:15 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("ELOG Version Detection");
  script_family("Service detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2009 SecPod");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("ELOG_HTTP/banner");
  script_require_ports("Services/www", 8080);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.901008";
SCRIPT_DESC = "ELOG Version Detection";

elogPort = get_http_port(default:8080);
if(!elogPort){
  elogPort = 8080;
}

if(!get_port_state(elogPort)){
  exit(0);
}

banner = get_http_banner(port:elogPort);
if("ELOG" >!< banner){
  exit(0);
}

elogVer = eregmatch(pattern:"Server: ELOG HTTP (([0-9.]+)-?([0-9]+)?)",
                     string:banner);
if(elogVer[1] != NULL)
{
  elogVer = ereg_replace(pattern:"-", string:elogVer[1], replace: ".");
  set_kb_item(name:"www/" + elogPort + "/ELOG", value:elogVer);
  log_message(data:"ELOG version " + elogVer + " was detected on the host");
   
  ## build cpe and store it as host_detail
  cpe = build_cpe(value:elogVer, exp:"^([0-9]+\.[0-9]+\.[0-9]+)", base:"cpe:/a:stefan_ritt:elog_web_logbook:");
  if(!isnull(cpe))
     register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

}
